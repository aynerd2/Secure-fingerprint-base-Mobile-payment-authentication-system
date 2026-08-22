package com.sfmpas.app.data

import com.google.gson.annotations.SerializedName
import okhttp3.OkHttpClient
import org.json.JSONObject
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

/**
 * Retrofit client for the SFMPAS backend hosted on Render.
 *
 * HTTPS only. Render terminates TLS for every `*.onrender.com` host, so the app
 * needs no `networkSecurityConfig` and no `usesCleartextTraffic` exemption —
 * cleartext stays blocked by the platform default, which is what we want.
 *
 * Timeouts are generous on purpose: Render's free tier suspends a web service
 * after ~15 minutes of inactivity, and the first request afterwards pays a cold
 * start of roughly 50 seconds while the instance boots. A default 10s timeout
 * would fail that first call every session.
 */
object ApiConfig {
    /**
     * Live backend. Change this if you name the Render service something other
     * than `sfmpas-backend` — Render derives the hostname from the service name.
     *
     * The trailing slash is required by Retrofit.
     */
    const val BASE_URL = "https://sfmpas-backend.onrender.com/"

    /** Long enough to absorb a free-tier cold start. */
    val CALL_TIMEOUT_SECONDS = 90L
    val CONNECT_TIMEOUT_SECONDS = 30L
}

// ---------------------------------------------------------------- DTOs

data class RegisterRequest(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("phone_number") val phoneNumber: String,
    @SerializedName("occupation") val occupation: String,
    @SerializedName("public_key") val publicKey: String,
)

data class RegisterResponse(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("occupation") val occupation: String,
    @SerializedName("registered_at") val registeredAt: String,
    @SerializedName("replaced_existing") val replacedExisting: Boolean,
)

data class AuthBeginRequest(
    @SerializedName("user_id") val userId: String,
    @SerializedName("amount_naira") val amountNaira: Long,
)

data class AuthBeginResponse(
    @SerializedName("challenge_id") val challengeId: String,
    /** Base64. Sign the RAW decoded bytes — nothing prepended or re-hashed. */
    @SerializedName("challenge") val challenge: String,
    @SerializedName("tier") val tier: String,
    @SerializedName("requirement") val requirement: String,
    @SerializedName("requires_liveness") val requiresLiveness: Boolean,
    @SerializedName("requires_enhanced") val requiresEnhanced: Boolean,
    @SerializedName("expires_at") val expiresAt: String,
)

data class AuthCompleteRequest(
    @SerializedName("user_id") val userId: String,
    /** Base64 DER ECDSA signature from the Keystore credential. */
    @SerializedName("assertion") val assertion: String,
    @SerializedName("amount_naira") val amountNaira: Long,
    @SerializedName("recipient") val recipient: String,
    @SerializedName("challenge_id") val challengeId: String? = null,
    @SerializedName("liveness_score") val livenessScore: Float? = null,
)

data class AuthCompleteResponse(
    @SerializedName("verdict") val verdict: String,
    @SerializedName("transaction_id") val transactionId: String,
    @SerializedName("amount_naira") val amountNaira: Long,
    @SerializedName("recipient") val recipient: String,
    @SerializedName("tier") val tier: String,
    @SerializedName("liveness_score") val livenessScore: Float?,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("receipt") val receipt: String?,
)

data class RemoteTransaction(
    @SerializedName("transaction_id") val transactionId: String,
    @SerializedName("amount_naira") val amountNaira: Long,
    @SerializedName("recipient") val recipient: String,
    @SerializedName("tier") val tier: String,
    @SerializedName("liveness_score") val livenessScore: Float?,
    @SerializedName("verdict") val verdict: String,
    @SerializedName("reason") val reason: String?,
    @SerializedName("created_at") val createdAt: String,
)

data class TransactionsResponse(
    @SerializedName("user_id") val userId: String,
    @SerializedName("count") val count: Int,
    @SerializedName("transactions") val transactions: List<RemoteTransaction>,
)

// ------------------------------------------------------------- service

interface SfmpasApi {

    @POST("register")
    suspend fun register(@Body body: RegisterRequest): RegisterResponse

    @POST("authenticate/begin")
    suspend fun authenticateBegin(@Body body: AuthBeginRequest): AuthBeginResponse

    @POST("authenticate/complete")
    suspend fun authenticateComplete(@Body body: AuthCompleteRequest): AuthCompleteResponse

    @GET("transactions")
    suspend fun transactions(@Query("user_id") userId: String): TransactionsResponse

    @GET("health")
    suspend fun health(): Map<String, String>
}

// -------------------------------------------------------------- client

/** Human-readable one-liner for a failed call, for on-screen diagnostics. */
fun describeNetworkError(t: Throwable): String = when (t) {
    is HttpException -> "HTTP ${t.code()}"
    is SocketTimeoutException -> "timed out (backend may be waking from sleep)"
    is UnknownHostException -> "host not found — check the network"
    is IOException -> "network error: ${t.message ?: "unknown"}"
    else -> t.message ?: t::class.java.simpleName
}

/**
 * Pulls the server's rejection reason out of an error response.
 *
 * `/authenticate/complete` returns `{"detail": {"verdict", "reason",
 * "transaction_id"}}` for a refusal, and FastAPI's validation errors put a plain
 * string in `detail`. Both shapes are handled; anything else degrades to the
 * status code rather than throwing while building an error message.
 */
fun extractServerReason(t: Throwable): String? {
    val http = t as? HttpException ?: return null
    val raw = runCatching { http.response()?.errorBody()?.string() }.getOrNull()
        ?: return "HTTP ${http.code()}"
    return runCatching {
        val detail = JSONObject(raw).get("detail")
        when (detail) {
            is JSONObject -> detail.optString("reason").ifBlank { detail.toString() }
            else -> detail.toString()
        }
    }.getOrElse { "HTTP ${http.code()}" }
}

object ApiClient {
    val api: SfmpasApi by lazy {
        val http = OkHttpClient.Builder()
            .callTimeout(ApiConfig.CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .connectTimeout(ApiConfig.CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(ApiConfig.CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()

        Retrofit.Builder()
            .baseUrl(ApiConfig.BASE_URL)
            .client(http)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SfmpasApi::class.java)
    }
}
