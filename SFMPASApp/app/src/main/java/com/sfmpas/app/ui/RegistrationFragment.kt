package com.sfmpas.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.sfmpas.app.R
import com.sfmpas.app.data.ApiClient
import com.sfmpas.app.data.BiometricSupport
import com.sfmpas.app.data.RegisterRequest
import com.sfmpas.app.data.describeNetworkError
import com.sfmpas.app.data.KeystoreManager
import com.sfmpas.app.data.SecurePrefs
import com.sfmpas.app.data.UserRepository
import com.sfmpas.app.databinding.FragmentRegistrationBinding
import com.sfmpas.app.model.Occupation
import com.sfmpas.app.model.UserProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Screen 1 — account registration.
 *
 * Flow: validate the form -> verify the user owns an enrolled fingerprint via
 * `BiometricPrompt` -> mint a Keystore-backed P-256 credential -> persist the
 * profile -> continue to Home.
 *
 * "Register Fingerprint" is a slight misnomer inherited from the spec: Android
 * does not let an app enrol a finger. What happens here is enrolment *check*,
 * ownership *verification*, and credential *binding*. If nothing is enrolled the
 * user is offered a jump to Settings.
 */
class RegistrationFragment : Fragment() {

    private var _binding: FragmentRegistrationBinding? = null
    private val binding get() = _binding!!

    private lateinit var users: UserRepository

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentRegistrationBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        users = UserRepository(requireContext())

        // Already registered? Skip straight to Home, popping this destination.
        // Posted rather than called inline: navigating out of the start
        // destination while it is still being laid out can race the graph.
        if (users.isRegistered()) {
            view.post {
                if (isAdded && findNavController().currentDestination?.id ==
                    R.id.registrationFragment
                ) {
                    findNavController().navigate(R.id.action_registration_to_home)
                }
            }
            return
        }

        binding.occupationGroup.setOnCheckedChangeListener { _, checkedId ->
            binding.occupationNote.visibility =
                if (checkedId == R.id.radioManual) View.VISIBLE else View.GONE
        }

        binding.registerButton.setOnClickListener { onRegisterClicked() }

        val availability = BiometricSupport.availability(requireContext())
        if (availability != BiometricSupport.Availability.READY) {
            showStatus(BiometricSupport.describe(availability))
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }

    // ------------------------------------------------------------------ flow

    private fun onRegisterClicked() {
        val name = binding.nameInput.text?.toString()?.trim().orEmpty()
        val phone = binding.phoneInput.text?.toString()?.trim().orEmpty()

        binding.nameLayout.error = if (name.length < 2) "Enter your full name" else null
        binding.phoneLayout.error = when {
            phone.isEmpty() -> "Enter your phone number"
            phone.filter { it.isDigit() }.length < 10 -> "Enter a valid phone number"
            else -> null
        }
        if (binding.nameLayout.error != null || binding.phoneLayout.error != null) return

        when (val availability = BiometricSupport.availability(requireContext())) {
            BiometricSupport.Availability.READY -> authenticateThenRegister(name, phone)
            BiometricSupport.Availability.NONE_ENROLLED -> {
                showStatus(BiometricSupport.describe(availability))
                runCatching { startActivity(BiometricSupport.enrolIntent()) }
                    .onFailure { showStatus("Could not open Settings: ${it.message}") }
            }
            else -> showStatus(BiometricSupport.describe(availability))
        }
    }

    private fun authenticateThenRegister(name: String, phone: String) {
        val executor = ContextCompat.getMainExecutor(requireContext())
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    completeRegistration(name, phone)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    showStatus("Registration cancelled: $message")
                }

                override fun onAuthenticationFailed() {
                    showStatus("Fingerprint not recognised. Try again.")
                }
            },
        )
        prompt.authenticate(
            BiometricSupport.prompt(
                title = "Register your fingerprint",
                subtitle = "Bind this device credential to your finger",
                description = "SFMPAS stores no fingerprint image. Only a key " +
                    "handle is kept, inside the secure hardware.",
            )
        )
    }

    private fun completeRegistration(name: String, phone: String) {
        val occupation =
            if (binding.occupationGroup.checkedRadioButtonId == R.id.radioManual) {
                Occupation.MANUAL_LABOUR_WORKER
            } else {
                Occupation.GENERAL_USER
            }

        val keyInfo = runCatching { KeystoreManager.createKeyPair() }
            .onFailure {
                showStatus("Could not create the device credential: ${it.message}")
                return
            }
            .getOrThrow()

        val userId = users.userId()
        users.save(
            UserProfile(
                userId = userId,
                fullName = name,
                phoneNumber = phone,
                occupation = occupation,
                registeredAtMillis = System.currentTimeMillis(),
            )
        )

        val localSummary = buildString {
            appendLine("Registration complete (on device).")
            appendLine("user id    : $userId")
            appendLine("credential : ${keyInfo.alias}")
            appendLine("algorithm  : EC P-256 / ${KeystoreManager.SIGNATURE_ALGORITHM}")
            appendLine("public key : ${keyInfo.publicKeyPreview}")
            appendLine("biometric-gated : ${keyInfo.userAuthenticationRequired}")
            appendLine("strongbox       : ${keyInfo.strongBoxBacked}")
            append("profile store   : ")
            append(if (SecurePrefs.usingEncryptedStore) "encrypted" else "plain (fallback)")
        }
        showStatus("$localSummary\n\nEnrolling public key with the backend…")
        binding.registerButton.isEnabled = false

        syncWithBackend(userId, name, phone, occupation, keyInfo.publicKeyB64, localSummary)
    }

    /**
     * POSTs the public key to /register.
     *
     * Registration is offline-first: the local enrolment above has already
     * succeeded, so a network failure downgrades to "pending sync" rather than
     * failing the whole flow. The user study can then run without a live
     * backend, and [AuthenticationFragment] re-tries the enrolment lazily the
     * first time it needs the server.
     *
     * The first call of a session can take ~50s while Render's free instance
     * wakes from sleep, which is why the OkHttp client allows 90s.
     */
    private fun syncWithBackend(
        userId: String,
        name: String,
        phone: String,
        occupation: Occupation,
        publicKeyB64: String,
        localSummary: String,
    ) {
        viewLifecycleOwner.lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    ApiClient.api.register(
                        RegisterRequest(
                            userId = userId,
                            username = name,
                            phoneNumber = phone,
                            occupation = occupation.name,
                            publicKey = publicKeyB64,
                        )
                    )
                }
            }
            if (!isAdded || _binding == null) return@launch

            outcome.onSuccess {
                users.setBackendSynced(true)
                showStatus("$localSummary\nbackend         : enrolled (${it.userId})")
            }.onFailure { error ->
                users.setBackendSynced(false)
                showStatus(
                    "$localSummary\nbackend         : UNREACHABLE — " +
                        "${describeNetworkError(error)}\n" +
                        "Continuing offline; the app will retry at payment time."
                )
            }

            binding.root.postDelayed({
                if (isAdded) findNavController().navigate(R.id.action_registration_to_home)
            }, 1600L)
        }
    }

    private fun showStatus(message: String) {
        _binding?.statusText?.apply {
            text = message
            visibility = View.VISIBLE
        }
    }
}
