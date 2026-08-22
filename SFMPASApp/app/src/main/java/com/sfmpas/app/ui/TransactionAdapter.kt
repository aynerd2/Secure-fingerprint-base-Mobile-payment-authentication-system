package com.sfmpas.app.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.sfmpas.app.R
import com.sfmpas.app.databinding.ItemTransactionBinding
import com.sfmpas.app.model.Transaction
import com.sfmpas.app.model.formatNaira

/** Renders the local transaction log, newest first. */
class TransactionAdapter(
    private var items: List<Transaction> = emptyList(),
) : RecyclerView.Adapter<TransactionAdapter.ViewHolder>() {

    class ViewHolder(val binding: ItemTransactionBinding) :
        RecyclerView.ViewHolder(binding.root)

    fun submit(newItems: List<Transaction>) {
        items = newItems
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
        ViewHolder(
            ItemTransactionBinding.inflate(
                LayoutInflater.from(parent.context), parent, false
            )
        )

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val tx = items[position]
        val context = holder.itemView.context
        val colour = ContextCompat.getColor(
            context,
            if (tx.approved) R.color.genuine_green else R.color.attack_red,
        )

        holder.binding.apply {
            recipientText.text = tx.recipient
            amountText.text = formatNaira(tx.amountNaira)
            detailText.text = buildString {
                append(tx.formattedTime())
                append(" · ")
                append(tx.tierName)
                append(" · liveness ")
                append(String.format("%.3f", tx.livenessScore))
                if (!tx.approved && tx.reason.isNotBlank()) {
                    append(" · ")
                    append(tx.reason)
                }
                // Distinguishes a server-verified payment from one settled on
                // device while the backend was unreachable, and carries the id
                // needed to reconcile this row against the server's audit trail.
                if (tx.isServerVerified) {
                    append("\n↑ server ")
                    append(tx.serverTransactionId?.take(8))
                } else if (tx.approved) {
                    append("\n○ offline — not server-verified")
                }
            }
            verdictText.text = if (tx.approved) "AUTHORISED" else "REJECTED"
            verdictText.setTextColor(colour)
            statusStripe.setBackgroundColor(colour)
        }
    }
}
