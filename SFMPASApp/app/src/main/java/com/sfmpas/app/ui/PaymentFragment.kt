package com.sfmpas.app.ui

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.core.os.bundleOf
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.sfmpas.app.R
import com.sfmpas.app.data.UserRepository
import com.sfmpas.app.databinding.FragmentPaymentBinding
import com.sfmpas.app.model.KycTier
import com.sfmpas.app.model.formatNaira

/**
 * Screen 3 — payment entry.
 *
 * The CBN KYC tier is recomputed on every keystroke so the user can see the
 * requirement change as the amount crosses ₦50,000 and ₦200,000.
 */
class PaymentFragment : Fragment() {

    private var _binding: FragmentPaymentBinding? = null
    private val binding get() = _binding!!

    private lateinit var users: UserRepository
    private var currentTier: KycTier? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentPaymentBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        users = UserRepository(requireContext())

        binding.amountInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) = onAmountChanged()
        })

        binding.recipientInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) = refreshProceedEnabled()
        })

        binding.proceedButton.setOnClickListener { onProceed() }

        refreshProceedEnabled()
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }

    // ------------------------------------------------------------ tier logic

    private fun parsedAmount(): Long? =
        binding.amountInput.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.toLongOrNull()

    private fun onAmountChanged() {
        val amount = parsedAmount()
        if (amount == null || amount <= 0L) {
            currentTier = null
            binding.tierChip.visibility = View.GONE
            binding.tierRangeText.visibility = View.GONE
            binding.tierRequirementText.text = getString(R.string.tier_prompt)
        } else {
            val tier = KycTier.forAmount(amount)
            currentTier = tier
            binding.tierChip.visibility = View.VISIBLE
            binding.tierChip.text = tier.displayName
            binding.tierRequirementText.text = tier.requirement
            binding.tierRangeText.visibility = View.VISIBLE
            binding.tierRangeText.text = getString(
                when (tier) {
                    KycTier.TIER_1 -> R.string.tier_range_1
                    KycTier.TIER_2 -> R.string.tier_range_2
                    KycTier.TIER_3 -> R.string.tier_range_3
                }
            )
        }
        binding.amountLayout.error = null
        refreshProceedEnabled()
    }

    /**
     * Keeps the affordability check live rather than deferring it to submit.
     *
     * Previously the button stayed enabled when the amount exceeded the balance,
     * so tapping it set an error and returned — which looked like the app had
     * frozen, with no route forward once the balance was spent.
     */
    private fun refreshProceedEnabled() {
        val amount = parsedAmount()
        val recipient = binding.recipientInput.text?.toString()?.trim().orEmpty()
        val balance = users.balance()

        val overdrawn = amount != null && amount > balance
        binding.amountLayout.error =
            if (overdrawn) getString(R.string.err_insufficient_funds, formatNaira(balance))
            else null

        binding.proceedButton.isEnabled =
            amount != null && amount > 0L && !overdrawn && recipient.isNotEmpty()

        // When there is nothing left to spend, say so and point at the fix
        // instead of leaving the user on a screen that cannot proceed.
        if (balance <= 0L) {
            binding.balanceHint.text = getString(R.string.balance_empty)
            binding.balanceHint.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.warn_amber)
            )
        } else {
            binding.balanceHint.text =
                getString(R.string.balance_hint, formatNaira(balance))
        }
    }

    // ---------------------------------------------------------------- action

    private fun onProceed() {
        val amount = parsedAmount()
        val recipient = binding.recipientInput.text?.toString()?.trim().orEmpty()

        binding.amountLayout.error = when {
            amount == null -> getString(R.string.err_amount_required)
            amount <= 0L -> getString(R.string.err_amount_positive)
            !users.canAfford(amount) ->
                getString(R.string.err_insufficient_funds, formatNaira(users.balance()))
            else -> null
        }
        binding.recipientLayout.error =
            if (recipient.isEmpty()) getString(R.string.err_recipient_required) else null

        if (binding.amountLayout.error != null || binding.recipientLayout.error != null) return
        val tier = currentTier ?: return
        val confirmedAmount: Long = amount ?: return

        findNavController().navigate(
            R.id.action_payment_to_authentication,
            bundleOf(
                "amountNaira" to confirmedAmount,
                "recipient" to recipient,
                "tierName" to tier.name,
            ),
        )
    }
}
