package com.bitwarden.network.ssl

import okhttp3.OkHttpClient
import timber.log.Timber
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
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
 * Creates default [TrustManager]s for verifying server certificates.
 *
 * Uses both system CA certificates and user-installed certificates.
 * This allows the app to trust self-signed certificates installed by the user
 * for testing purposes (e.g., with self-hosted Bitwarden servers).
 */
private val sslTrustManagers: Array<TrustManager>
    get() = runCatching {
        // Try AndroidCAStore first (includes both system and user certificates)
        val keyStore = KeyStore.getInstance("AndroidCAStore").apply { load(null) }

        // Debug: Log all certificates in the keystore
        val aliases = keyStore.aliases().toList()
        Timber.d("=== SSL Trust Manager Debug ===")
        Timber.d("Total certificates in AndroidCAStore: ${aliases.size}")

        var systemCount = 0
        var userCount = 0

        aliases.forEach { alias ->
            val cert = keyStore.getCertificate(alias) as? X509Certificate
            cert?.let {
                val isUserCert = alias.contains("user:", ignoreCase = true)
                if (isUserCert) {
                    userCount++
                    Timber.d("USER CA: $alias")
                    Timber.d("  Subject: ${it.subjectDN}")
                    Timber.d("  Issuer: ${it.issuerDN}")
                    Timber.d("  Valid from: ${it.notBefore} to ${it.notAfter}")
                } else {
                    systemCount++
                }
            }
        }
        Timber.d("System CAs: $systemCount, User CAs: $userCount")
        Timber.d("================================")

        TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore) }
            .trustManagers
    }.getOrElse { error ->
        Timber.e(error, "Failed to load AndroidCAStore, using default trust managers")
        // Fallback to default trust managers if AndroidCAStore fails
        TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as KeyStore?) }
            .trustManagers
    }
