package com.sfmpas.app.ui

import android.graphics.Bitmap
import android.util.Base64
import android.util.Log
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.OnBackPressedCallback
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.sfmpas.app.PadInferenceEngine
import com.sfmpas.app.R
import com.sfmpas.app.data.ApiClient
import com.sfmpas.app.data.AuthBeginRequest
import com.sfmpas.app.data.AuthCompleteRequest
import com.sfmpas.app.data.BiometricSupport
import com.sfmpas.app.data.RegisterRequest
import com.sfmpas.app.data.describeNetworkError
import com.sfmpas.app.data.extractServerReason
import com.sfmpas.app.data.KeystoreManager
import com.sfmpas.app.data.ReferencePrints
import com.sfmpas.app.data.TransactionStore
import com.sfmpas.app.data.UserRepository
import com.sfmpas.app.databinding.FragmentAuthenticationBinding
import com.sfmpas.app.model.KycTier
import com.sfmpas.app.model.Transaction
import com.sfmpas.app.model.formatNaira
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.security.Signature
import java.util.UUID
import kotlin.math.roundToInt

/**
 * Screen 4 — step-up authentication.
 *
 * Sequence:
 *   1. PAD liveness on the captured print (always run and always displayed).
 *   2. Fingerprint verification via `BiometricPrompt`, producing a FIDO2-style
 *      ECDSA assertion over the transaction using the Keystore credential.
 *   3. Tier 3 only: enhanced verification, which additionally accepts the device
 *      credential and re-confirms the amount.
 *
 * On the liveness/tier interaction: the brief says this screen always runs the
 * PAD check, while Tier 1 is defined as "fingerprint only". Both are honoured —
 * the check always runs and the score is always shown, but a FAIL only *blocks*
 * at Tier 2 and Tier 3. At Tier 1 the score is recorded as informational. The
 * label under the verdict states which applies, so the distinction is visible
 * during a demo.
 */
class AuthenticationFragment : Fragment() {

    private var _binding: FragmentAuthenticationBinding? = null
    private val binding get() = _binding!!

    private lateinit var users: UserRepository
    private lateinit var transactions: TransactionStore

    private var engine: PadInferenceEngine? = null
    private var previewBitmap: Bitmap? = null

    private var amountNaira: Long = 0L
    private lateinit var recipient: String
    private lateinit var tier: KycTier

    private companion object {
        const val TAG = "SFMPAS/Auth"
    }

    /** At or above this the wording strengthens; the accept cut-off stays 0.5. */
    private val HIGH_CONFIDENCE = 0.90f

    private var livenessJob: Job? = null
    private var backendOnline = false
    private var serverChallenge: String? = null
    private var serverChallengeId: String? = null
    private var livenessScore: Float = Float.NaN
    private var livenessPassed = false
    private var terminal = false

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentAuthenticationBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        users = UserRepository(requireContext())
        transactions = TransactionStore(requireContext())

        val args = requireArguments()
        amountNaira = args.getLong("amountNaira")
        recipient = args.getString("recipient").orEmpty()
        tier = runCatching { KycTier.valueOf(args.getString("tierName").orEmpty()) }
            .getOrDefault(KycTier.forAmount(amountNaira))

        binding.summaryAmount.text = formatNaira(amountNaira)
        binding.summaryRecipient.text = "to $recipient · ${tier.displayName}"
        binding.enforcementText.text =
            if (tier.requiresLiveness) getString(R.string.enforced_at, tier.displayName)
            else getString(R.string.not_enforced_tier1)

        binding.primaryButton.setOnClickListener { onPrimaryClicked() }
        binding.secondaryButton.setOnClickListener { runLivenessCheck() }
        binding.simulateAttackSwitch.setOnCheckedChangeListener { _, _ ->
            if (!terminal) runLivenessCheck()
        }

        // Once a verdict is reached, Back returns to Home rather than to the
        // payment form, so a completed authorisation cannot be re-entered.
        requireActivity().onBackPressedDispatcher.addCallback(
            viewLifecycleOwner,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    if (terminal) goHome() else {
                        isEnabled = false
                        requireActivity().onBackPressedDispatcher.onBackPressed()
                    }
                }
            },
        )

        runLivenessCheck()
    }

    override fun onDestroyView() {
        livenessJob?.cancel()
        livenessJob = null
        engine?.close()
        engine = null
        previewBitmap?.recycle()
        previewBitmap = null
        _binding = null
        super.onDestroyView()
    }

    // ------------------------------------------------------- 1 · PAD liveness

    private fun runLivenessCheck() {
        // A TFLite Interpreter is not thread-safe. Toggling the attack switch
        // during a run would otherwise start a second coroutine sharing the same
        // interpreter and input buffer, which can wedge or crash the app.
        if (livenessJob?.isActive == true) return
        binding.simulateAttackSwitch.isEnabled = false
        binding.livenessProgress.visibility = View.VISIBLE
        binding.primaryButton.isEnabled = false
        binding.secondaryButton.visibility = View.GONE
        binding.resultCard.visibility = View.GONE
        binding.verdictText.text = ""
        binding.scoreText.text = getString(R.string.liveness_running)
        binding.logText.visibility = View.GONE
        terminal = false

        val useAttack = binding.simulateAttackSwitch.isChecked
        val index = if (useAttack) ReferencePrints.ATTACK else ReferencePrints.GENUINE

        livenessJob = viewLifecycleOwner.lifecycleScope.launch {
            val outcome = withContext(Dispatchers.Default) {
                runCatching {
                    val reference = ReferencePrints.load(requireContext(), index)
                    val padEngine = engine
                        ?: PadInferenceEngine(requireContext()).also { engine = it }
                    val score = padEngine.score(reference.bitmap)
                    reference to score
                }
            }
            if (!isAdded || _binding == null) return@launch
            binding.livenessProgress.visibility = View.GONE
            binding.simulateAttackSwitch.isEnabled = !terminal

            outcome.onSuccess { (reference, score) ->
                // Attach the new bitmap BEFORE recycling the old one — the
                // ImageView still references the old until setImageBitmap lands.
                val previous = previewBitmap
                previewBitmap = reference.bitmap
                binding.printPreview.setImageBitmap(reference.bitmap)
                previous?.recycle()
                renderLivenessVerdict(score, reference.source)
            }.onFailure { error ->
                binding.verdictText.text = "ERROR"
                binding.verdictText.setTextColor(colour(R.color.attack_red))
                binding.scoreText.text = error.message ?: error::class.java.simpleName
                finish(false, "Liveness engine failed: ${error.message}", "")
            }
        }
    }

    private fun renderLivenessVerdict(score: Float, source: String) {
        livenessScore = score
        livenessPassed = score >= PadInferenceEngine.DEFAULT_THRESHOLD

        // Participants read a plain-language verdict; the number stays, but
        // smaller and underneath, expressed as a percentage rather than a raw
        // model output. HIGH_CONFIDENCE only changes the wording — the accept
        // decision is still the 0.5 threshold the model was evaluated at.
        binding.verdictText.text = getString(
            when {
                score >= HIGH_CONFIDENCE -> R.string.liveness_real_confirmed
                livenessPassed -> R.string.liveness_passed
                else -> R.string.liveness_fake
            }
        )
        binding.verdictText.setTextColor(
            colour(if (livenessPassed) R.color.genuine_green else R.color.attack_red)
        )
        binding.scoreText.text =
            getString(R.string.confidence_fmt, (score * 100f).roundToInt())

        binding.logText.visibility = View.VISIBLE
        binding.logText.text = buildString {
            appendLine(getString(
                if (source.contains("Zcut", ignoreCase = true)) R.string.log_sample_altered
                else R.string.log_sample_genuine
            ))
            append(getString(
                if (livenessPassed) R.string.log_liveness_pass
                else R.string.log_liveness_fail
            ))
            if (!livenessPassed && !tier.requiresLiveness) {
                append("  ")
                append(getString(R.string.log_not_enforced, tier.displayName))
            }
        }

        if (!livenessPassed && tier.requiresLiveness) {
            // Blocking failure: the payment stops here.
            binding.primaryButton.isEnabled = false
            finish(
                requestedApproval = false,
                requestedReason = "Presentation attack detected (score %.4f < %.2f)".format(
                    score, PadInferenceEngine.DEFAULT_THRESHOLD
                ),
                assertion = "",
            )
        } else {
            binding.primaryButton.isEnabled = true
        }
    }

    // ------------------------------------------------ 2 · fingerprint + FIDO2

    private fun onPrimaryClicked() {
        if (terminal) goHome() else startAuthorisation()
    }

    /**
     * Step 2 begins with a round trip: the challenge must come from the server,
     * not the device.
     *
     * A locally-invented challenge proves nothing — an attacker who captured one
     * assertion could replay it, or sign a payload the server never issued. So we
     * call /authenticate/begin first and sign exactly the bytes it returns.
     *
     * If the backend cannot be reached the flow degrades to a device-local
     * challenge and the transaction is recorded as locally verified, so a user
     * study can run without connectivity. That fallback is announced in the log
     * rather than hidden.
     */
    private fun startAuthorisation() {
        when (val availability = BiometricSupport.availability(requireContext())) {
            BiometricSupport.Availability.READY -> Unit
            else -> {
                finish(false, BiometricSupport.describe(availability), "")
                return
            }
        }

        binding.primaryButton.isEnabled = false
        binding.livenessProgress.visibility = View.VISIBLE
        appendLog(getString(R.string.log_contacting))

        viewLifecycleOwner.lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    // Registration may have happened offline; enrol lazily so the
                    // first online payment still works.
                    if (!users.isBackendSynced()) {
                        val profile = users.load()
                        val publicKey = KeystoreManager.publicKeyB64()
                        if (profile != null && publicKey != null) {
                            ApiClient.api.register(
                                RegisterRequest(
                                    userId = users.userId(),
                                    username = profile.fullName,
                                    phoneNumber = profile.phoneNumber,
                                    occupation = profile.occupation.name,
                                    publicKey = publicKey,
                                )
                            )
                            users.setBackendSynced(true)
                        }
                    }
                    ApiClient.api.authenticateBegin(
                        AuthBeginRequest(users.userId(), amountNaira)
                    )
                }
            }
            if (!isAdded || _binding == null) return@launch
            binding.livenessProgress.visibility = View.GONE

            outcome.onSuccess { begin ->
                backendOnline = true
                serverChallenge = begin.challenge
                serverChallengeId = begin.challengeId
                appendLog(getString(R.string.log_session_started))
                if (begin.tier != tier.name) {
                    // The server is authoritative on tiering; surface any drift
                    // rather than silently using the device's opinion.
                    // Kept technical: a tier disagreement is a defect worth
                    // seeing, not something to soften for a participant.
                    appendLog("NOTE: server tier " + begin.tier +
                        " != device " + tier.name)
                }
            }.onFailure { error ->
                backendOnline = false
                serverChallenge = null
                serverChallengeId = null
                setOfflineBanner(true)
                // Participants get plain language; the actual cause goes to
                // logcat so it is still recoverable when debugging a session.
                Log.w(TAG, "authenticate/begin failed: " + describeNetworkError(error))
                appendLog(getString(R.string.log_server_offline))
            }

            promptForFingerprint()
        }
    }

    private fun promptForFingerprint() {
        val signature: Signature? = try {
            KeystoreManager.signatureForSigning()
        } catch (e: KeyPermanentlyInvalidatedException) {
            finish(
                false,
                "Device credential invalidated by a new fingerprint enrolment. " +
                    "Please register again.",
                "",
            )
            return
        } catch (t: Throwable) {
            null
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(requireContext()),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    val assertion = signAssertion(result.cryptoObject?.signature)
                    appendLog(getString(R.string.log_fingerprint_pass))
                    if (tier.requiresEnhanced) {
                        beginEnhancedVerification(assertion)
                    } else {
                        completeWithBackend(assertion)
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    finish(false, "Fingerprint verification cancelled: $message", "")
                }

                override fun onAuthenticationFailed() {
                    appendLog(getString(R.string.log_fingerprint_fail))
                }
            },
        )

        val info = BiometricSupport.prompt(
            title = "Authorise ${formatNaira(amountNaira)}",
            subtitle = "to $recipient",
            description = "${tier.displayName} - ${tier.requirement}",
        )
        if (signature != null) {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
        } else {
            prompt.authenticate(info)
        }
    }

    /**
     * Signs the server-issued challenge if we have one, otherwise a device-local
     * payload. The server verifies over the RAW decoded challenge bytes —
     * nothing prepended, appended, or re-hashed.
     */
    private fun signAssertion(signature: Signature?): String {
        if (signature == null) return "(unsigned - credential is not biometric-gated)"
        val payload = serverChallenge
            ?.let { Base64.decode(it, Base64.NO_WRAP) }
            ?: KeystoreManager.challengeFor(
                recipient, amountNaira, System.currentTimeMillis()
            )
        return runCatching {
            signature.update(payload)
            KeystoreManager.encodeSignature(signature.sign())
        }.getOrElse { "(signing failed: ${it.message})" }
    }

    // ----------------------------------------- 3 - Tier 3 enhanced verification

    private fun beginEnhancedVerification(assertion: String) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(requireContext()),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    appendLog(getString(R.string.log_enhanced_pass))
                    completeWithBackend(assertion)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    finish(false, "Enhanced verification cancelled: $message", "")
                }
            },
        )
        prompt.authenticate(
            BiometricSupport.enhancedPrompt(
                title = "Enhanced verification",
                subtitle = "Tier 3 - ${formatNaira(amountNaira)}",
                description = "Confirm ${formatNaira(amountNaira)} to $recipient. " +
                    "Transactions above 200,000 Naira require a second factor.",
            )
        )
    }

    // ------------------------------------------- 4 - server-side authorisation

    /**
     * Submits the assertion for server verification. The backend's verdict is
     * authoritative when it answers: an HTTP error means it actively refused
     * (bad signature, replay, expired or mismatched challenge), which must not
     * be treated as an approval. A transport failure is different — that is the
     * offline case, and the payment is recorded as locally verified.
     */
    private fun completeWithBackend(assertion: String) {
        if (!backendOnline || serverChallengeId == null) {
            // No challenge was ever issued, so there is nothing the server can
            // verify. Keep the banner up for the whole screen.
            setOfflineBanner(true)
            finish(true, "Verified on device (backend unreachable)", assertion)
            return
        }

        binding.livenessProgress.visibility = View.VISIBLE
        appendLog(getString(R.string.log_sending))

        viewLifecycleOwner.lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    ApiClient.api.authenticateComplete(
                        AuthCompleteRequest(
                            userId = users.userId(),
                            assertion = assertion,
                            amountNaira = amountNaira,
                            recipient = recipient,
                            challengeId = serverChallengeId,
                            livenessScore =
                                if (livenessScore.isNaN()) null else livenessScore,
                        )
                    )
                }
            }
            if (!isAdded || _binding == null) return@launch
            binding.livenessProgress.visibility = View.GONE

            outcome.onSuccess { response ->
                Log.i(TAG, "server transaction " + response.transactionId)
                appendLog(getString(R.string.log_server_confirmed))
                finish(true, "Verified by backend", assertion, response.transactionId)
            }.onFailure { error ->
                if (error is HttpException) {
                    // An HTTP error means the server actively refused. That is a
                    // rejection, not an outage, so the banner stays down.
                    val reason = extractServerReason(error)
                        ?: "backend rejected the assertion"
                    appendLog(getString(R.string.log_server_declined, reason))
                    finish(false, reason, assertion)
                } else {
                    // Transport failure: we could not ask, so fall back to the
                    // local verdict and say so.
                    backendOnline = false
                    setOfflineBanner(true)
                    Log.w(TAG, "authenticate/complete failed: " +
                        describeNetworkError(error))
                    appendLog(getString(R.string.log_server_unreachable))
                    finish(true, "Verified on device (backend unreachable)", assertion)
                }
            }
        }
    }

    // ---------------------------------------------------------------- verdict

    private fun finish(
        requestedApproval: Boolean,
        requestedReason: String,
        assertion: String,
        serverTransactionId: String? = null,
    ) {
        if (terminal) return
        // Biometric callbacks can land after the view is gone (rotation, back).
        val binding = _binding ?: return
        terminal = true

        // Settle the ledger before declaring success. `debit` refuses to
        // overdraw and returns false, so an unaffordable payment is reported as
        // rejected rather than being clamped to zero and shown as authorised.
        var approved = requestedApproval
        var reason = requestedReason
        if (approved && !users.debit(amountNaira)) {
            approved = false
            reason = getString(
                R.string.err_insufficient_funds, formatNaira(users.balance())
            )
        }

        transactions.add(
            Transaction(
                id = UUID.randomUUID().toString(),
                recipient = recipient,
                amountNaira = amountNaira,
                tierName = tier.displayName,
                timestampMillis = System.currentTimeMillis(),
                approved = approved,
                livenessScore = livenessScore,
                livenessEnforced = tier.requiresLiveness,
                reason = reason,
                signaturePreview = assertion.take(24),
                serverTransactionId = serverTransactionId,
            )
        )

        val accent = colour(if (approved) R.color.genuine_green else R.color.attack_red)
        val background =
            colour(if (approved) R.color.genuine_green_dim else R.color.attack_red_dim)

        binding.resultCard.visibility = View.VISIBLE
        binding.resultCard.setCardBackgroundColor(background)
        binding.resultIcon.text = if (approved) "✓" else "✕"
        binding.resultIcon.setTextColor(accent)
        binding.resultTitle.setTextColor(accent)
        binding.resultTitle.text =
            getString(if (approved) R.string.payment_authorised else R.string.payment_rejected)
        binding.resultDetail.text = if (approved) {
            "${formatNaira(amountNaira)} to $recipient\n${tier.displayName} · ${tier.requirement}"
        } else {
            reason
        }
        // Only claim a signature when one was actually produced. The Keystore
        // falls back to an ungated key on some devices, and signAssertion then
        // returns a "(...)" placeholder — asserting "digitally signed" there
        // would be untrue in front of a study participant.
        val reallySigned = approved && assertion.isNotBlank() && !assertion.startsWith("(")
        binding.resultSignature.visibility = if (reallySigned) View.VISIBLE else View.GONE
        binding.resultSignature.text = getString(R.string.signed_verified)

        binding.simulateAttackSwitch.isEnabled = false
        binding.primaryButton.isEnabled = true
        binding.primaryButton.text = getString(R.string.btn_done)
        binding.secondaryButton.visibility = if (approved) View.GONE else View.VISIBLE
        binding.secondaryButton.text = getString(R.string.btn_retry)

        // The server transaction id is deliberately NOT shown here — it is a
        // reconciliation handle, kept on the stored record and in the history
        // list rather than put in front of a study participant.
        appendLog(
            if (approved) getString(R.string.log_verdict_approved)
            else getString(R.string.log_verdict_blocked) + " - " + reason
        )
    }

    /**
     * Returns to Home, clearing the whole payment leg so another payment can be
     * started immediately. Guarded against a double tap of Done (or Done racing
     * a Back press), which would otherwise throw because the action is no longer
     * valid once the destination has changed.
     */
    /**
     * Shows or hides the amber offline banner.
     *
     * Driven only by an actual call failure, never by a guess — the app should
     * not claim to be offline before it has tried. Once raised it stays up for
     * the rest of the screen, since a later call succeeding does not change the
     * fact that this authorisation was settled without the server.
     */
    private fun setOfflineBanner(visible: Boolean) {
        _binding?.offlineBanner?.visibility = if (visible) View.VISIBLE else View.GONE
    }

    private fun goHome() {
        val nav = findNavController()
        if (nav.currentDestination?.id == R.id.authenticationFragment) {
            nav.navigate(R.id.action_authentication_to_home)
        }
    }

    private fun appendLog(line: String) {
        _binding?.logText?.apply {
            visibility = View.VISIBLE
            text = "${text}\n$line"
        }
    }

    private fun colour(resId: Int): Int = ContextCompat.getColor(requireContext(), resId)
}
