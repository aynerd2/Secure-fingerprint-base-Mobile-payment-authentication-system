package com.sfmpas.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import com.sfmpas.app.R
import com.sfmpas.app.data.TransactionStore
import com.sfmpas.app.data.UserRepository
import com.sfmpas.app.databinding.FragmentHomeBinding
import com.sfmpas.app.model.formatNaira

/**
 * Screen 2 — account home. Shows the registered user, their account tier and
 * mock balance, and gates entry to the payment flow.
 *
 * Transaction history is an inline expanding section rather than a separate
 * destination, so the flow stays four screens deep as specified.
 */
class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!

    private lateinit var users: UserRepository
    private lateinit var transactions: TransactionStore
    private val adapter = TransactionAdapter()
    private var historyVisible = false

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        users = UserRepository(requireContext())
        transactions = TransactionStore(requireContext())

        binding.historyList.layoutManager = LinearLayoutManager(requireContext())
        binding.historyList.adapter = adapter

        binding.makePaymentButton.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_payment)
        }
        binding.selfTestButton.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_self_test)
        }
        binding.historyButton.setOnClickListener { toggleHistory() }
        binding.resetBalanceButton.setOnClickListener { onResetBalance() }
    }

    /**
     * Restores the demo float for the user study. Deliberately resets *only* the
     * balance — the registration, Keystore credential and transaction log all
     * survive, so a session can be repeated without re-enrolling a fingerprint.
     */
    private fun onResetBalance() {
        val restored = users.resetBalance()
        renderAccount()
        Snackbar.make(
            binding.root,
            getString(R.string.balance_reset_done, formatNaira(restored)),
            Snackbar.LENGTH_SHORT,
        ).show()
    }

    override fun onResume() {
        super.onResume()
        renderAccount()
        if (historyVisible) renderHistory()
    }

    override fun onDestroyView() {
        binding.historyList.adapter = null
        _binding = null
        super.onDestroyView()
    }

    private fun renderAccount() {
        val profile = users.load() ?: return
        val balance = users.balance()
        binding.welcomeText.text = getString(R.string.home_welcome, profile.firstName)
        binding.phoneText.text = "${profile.phoneNumber} · ${profile.occupation.displayName}"
        binding.tierChip.text = profile.accountTier
        binding.balanceText.text = formatNaira(balance)

        // Spent out: surface it here and keep Make Payment inert, rather than
        // letting the user reach a payment screen that cannot proceed.
        val empty = balance <= 0L
        binding.lowBalanceWarning.visibility = if (empty) View.VISIBLE else View.GONE
        binding.makePaymentButton.isEnabled = !empty
    }

    private fun toggleHistory() {
        historyVisible = !historyVisible
        if (historyVisible) renderHistory() else hideHistory()
    }

    private fun renderHistory() {
        val log = transactions.all()
        adapter.submit(log)
        binding.historyList.visibility = if (log.isEmpty()) View.GONE else View.VISIBLE
        binding.emptyHistoryText.visibility = if (log.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun hideHistory() {
        binding.historyList.visibility = View.GONE
        binding.emptyHistoryText.visibility = View.GONE
    }
}
