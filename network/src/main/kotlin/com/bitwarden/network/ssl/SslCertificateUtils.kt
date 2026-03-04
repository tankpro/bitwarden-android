package com.bitwarden.network.ssl

import okhttp3.OkHttpClient
import timber.log.Timber
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Creates an [OkHttpClient] configured with mTLS support using this [CertificateProvider].
 *
 * The returned client will present the client certificate from this provider during TLS
 * handshakes, allowing requests to pass through mTLS checks.
 */
fun CertificateProvider.createMtlsOkHttpClient(): OkHttpClient =
    OkHttpClient.Builder()
        .configureSsl(certificateProvider = this)
        .build()

/**
 * Configures the [OkHttpClient.Builder] to use the a `SSLSocketFactory` as provided by the
 * [CertificateProvider].
 */
fun OkHttpClient.Builder.configureSsl(
    certificateProvider: CertificateProvider,
): OkHttpClient.Builder {
    val trustManagers = sslTrustManagers
    val sslContext = certificateProvider.createSslContext(trustManagers = trustManagers)
    return sslSocketFactory(
        sslContext.socketFactory,
        trustManagers.first() as X509TrustManager,
    )
}

/**
 * Creates an [SSLContext] configured with mTLS support using this [CertificateProvider].
 *
 * The returned SSLContext will present the client certificate from this provider during
 * TLS handshakes, enabling mutual TLS authentication.
 */
private fun CertificateProvider.createSslContext(
    trustManagers: Array<TrustManager>,
): SSLContext = SSLContext.getInstance("TLS").apply {
    init(
        arrayOf(
            BitwardenX509ExtendedKeyManager(certificateProvider = this@createSslContext),
        ),
        trustManagers,
        null,
    )
}

/**
 * Trust manager that accepts all certificates.
 * This is useful for development/testing with self-hosted servers using self-signed certificates.
 *
 * WARNING: This should NOT be used in production builds as it disables SSL certificate verification.
 */
private class TrustAllX509TrustManager : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Trust all client certificates
        Timber.d("Trusting client certificate: ${chain?.firstOrNull()?.subjectDN}")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Trust all server certificates
        Timber.d("Trusting server certificate: ${chain?.firstOrNull()?.subjectDN}")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/**
 * Creates [TrustManager]s that trust all certificates.
 *
 * WARNING: This disables SSL certificate verification entirely. Use only for
 * development/testing with self-hosted servers.
 */
private val sslTrustManagers: Array<TrustManager>
    get() = runCatching {
        Timber.w("=== SSL WARNING: Trusting ALL certificates ===")
        Timber.w("This configuration trusts all SSL certificates without verification.")
        Timber.w("Only use this for development/testing with self-hosted servers.")
        Timber.w("==============================================")

        // Create a trust manager that accepts all certificates
        arrayOf<TrustManager>(TrustAllX509TrustManager())
    }.getOrElse { error ->
        Timber.e(error, "Failed to create trust manager")
        arrayOf<TrustManager>(TrustAllX509TrustManager())
    }