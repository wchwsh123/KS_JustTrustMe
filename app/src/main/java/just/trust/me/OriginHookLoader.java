package just.trust.me;

import static de.robv.android.xposed.XC_MethodReplacement.DO_NOTHING;
import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.findClass;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.newInstance;
import static de.robv.android.xposed.XposedHelpers.setObjectField;

import android.content.Context;
import android.net.http.SslError;
import android.net.http.X509TrustManagerExtensions;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;

import org.apache.http.conn.scheme.HostNameResolver;
import org.apache.http.conn.ssl.SSLSocketFactory;

import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class OriginHookLoader implements HookLoader {

    private static final String TAG = "JustTrustMe";

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        final String currentPackageName = lpparam.packageName;
        HookUtils.processDefaultHttp(TAG, currentPackageName);

        findAndHookMethod(X509TrustManagerExtensions.class, "checkServerTrusted", X509Certificate[].class, String.class, String.class, new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return param.args[0];
            }
        });

        findAndHookMethod("android.security.net.config.NetworkSecurityTrustManager", lpparam.classLoader, "checkPins", List.class, DO_NOTHING);

        /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
        /* public SSLSocketFactory( ... ) */
        try {
            Log.d(TAG, String.format("Hooking SSLSocketFactory(String, KeyStore, String, KeyStore) for: %s", currentPackageName));
            findAndHookConstructor(SSLSocketFactory.class, String.class, KeyStore.class, String.class, KeyStore.class, SecureRandom.class, HostNameResolver.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                    String algorithm = (String) param.args[0];
                    KeyStore keystore = (KeyStore) param.args[1];
                    String keystorePassword = (String) param.args[2];
                    SecureRandom random = (SecureRandom) param.args[4];

                    KeyManager[] keymanagers = null;
                    TrustManager[] trustmanagers = null;

                    if (keystore != null) {
                        keymanagers = (KeyManager[]) callStaticMethod(SSLSocketFactory.class, "createKeyManagers", keystore, keystorePassword);
                    }

                    trustmanagers = new TrustManager[]{new ImSureItsLegitTrustManager()};

                    setObjectField(param.thisObject, "sslcontext", SSLContext.getInstance(algorithm));
                    callMethod(getObjectField(param.thisObject, "sslcontext"), "init", keymanagers, trustmanagers, random);
                    setObjectField(param.thisObject, "socketfactory", callMethod(getObjectField(param.thisObject, "sslcontext"), "getSocketFactory"));
                }

            });


            /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
            /* public static SSLSocketFactory getSocketFactory() */
            Log.d(TAG, "Hooking static SSLSocketFactory(String, KeyStore, String, KeyStore) for: " + currentPackageName);
            findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "getSocketFactory", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return (SSLSocketFactory) newInstance(SSLSocketFactory.class);
                }
            });
        } catch (NoClassDefFoundError e) {
            Log.d(TAG, "NoClassDefFoundError SSLSocketFactory HostNameResolver for: " + currentPackageName);
        }

        /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
        /* public boolean isSecure(Socket) */
        Log.d(TAG, "Hooking SSLSocketFactory(Socket) for: " + currentPackageName);
        findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure", Socket.class, DO_NOTHING);

        /* JSSE Hooks */
        /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
        /* public final TrustManager[] getTrustManager() */
        Log.d(TAG, "Hooking TrustManagerFactory.getTrustManagers() for: " + currentPackageName);
        findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                if (HookUtils.hasTrustManagerImpl()) {
                    Class<?> cls = findClass("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader);

                    TrustManager[] managers = (TrustManager[]) param.getResult();
                    if (managers.length > 0 && cls.isInstance(managers[0])) return;
                }

                param.setResult(new TrustManager[]{new ImSureItsLegitTrustManager()});
            }
        });

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setDefaultHostnameVerifier(HostnameVerifier) */
        Log.d(TAG, "Hooking HttpsURLConnection.setDefaultHostnameVerifier for: " + currentPackageName);
        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier", HostnameVerifier.class, DO_NOTHING);

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setSSLSocketFactory(SSLSocketFactory) */
        Log.d(TAG, "Hooking HttpsURLConnection.setSSLSocketFactory for: " + currentPackageName);
        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", javax.net.ssl.SSLSocketFactory.class, DO_NOTHING);

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setHostnameVerifier(HostNameVerifier) */
        Log.d(TAG, "Hooking HttpsURLConnection.setHostnameVerifier for: " + currentPackageName);
        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier", HostnameVerifier.class, DO_NOTHING);


        /* WebView Hooks */
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        Log.d(TAG, "Hooking WebViewClient.onReceivedSslError(WebView, SslErrorHandler, SslError) for: " + currentPackageName);

        findAndHookMethod("android.webkit.WebViewClient", lpparam.classLoader, "onReceivedSslError", WebView.class, SslErrorHandler.class, SslError.class, new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                ((android.webkit.SslErrorHandler) param.args[1]).proceed();
                return null;
            }
        });

        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedError(WebView, int, String, String) */
        Log.d(TAG, "Hooking WebViewClient.onReceivedSslError(WebView, int, string, string) for: " + currentPackageName);

        findAndHookMethod("android.webkit.WebViewClient", lpparam.classLoader, "onReceivedError", WebView.class, int.class, String.class, String.class, DO_NOTHING);

        //SSLContext.init >> (null,ImSureItsLegitTrustManager,null)
        findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init", KeyManager[].class, TrustManager[].class, SecureRandom.class, new XC_MethodHook() {

            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                param.args[0] = null;
                param.args[1] = new TrustManager[]{new ImSureItsLegitTrustManager()};
                param.args[2] = null;

            }
        });

        // Multi-dex support: https://github.com/rovo89/XposedBridge/issues/30#issuecomment-68486449
        findAndHookMethod("android.app.Application", lpparam.classLoader, "attach", Context.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                // Hook OkHttp or third party libraries.
                final Context context = (Context) param.args[0];
                HookUtils.processOkHttp(TAG, context.getClassLoader(), currentPackageName);
                HookUtils.processHttpClientAndroidLib(TAG, context.getClassLoader(), currentPackageName);
                HookUtils.processXutils(TAG, context.getClassLoader(), currentPackageName);
            }
        });

        /* Only for newer devices should we try to hook TrustManagerImpl */
        if (HookUtils.hasTrustManagerImpl()) {
            /* TrustManagerImpl Hooks */
            /* external/conscrypt/src/platform/java/org/conscrypt/TrustManagerImpl.java */
            Log.d(TAG, "Hooking com.android.org.conscrypt.TrustManagerImpl for: " + currentPackageName);

            /* public void checkServerTrusted(X509Certificate[] chain, String authType) */
            findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader, "checkServerTrusted", X509Certificate[].class, String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return 0;
                }
            });

            /* public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                    String authType, String host) throws CertificateException */
            findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader, "checkServerTrusted", X509Certificate[].class, String.class, String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return new ArrayList<>();
                }
            });


            /* public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                    String authType, SSLSession session) throws CertificateException */
            findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader, "checkServerTrusted", X509Certificate[].class, String.class, SSLSession.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return new ArrayList<>();
                }
            });

            try {
                findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader, "checkTrusted", X509Certificate[].class, String.class, SSLSession.class, SSLParameters.class, boolean.class, new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return new ArrayList<>();
                    }
                });


                findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader, "checkTrusted", X509Certificate[].class, byte[].class, byte[].class, String.class, String.class, boolean.class, new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return new ArrayList<>();
                    }
                });
            } catch (NoSuchMethodError e) {
                //
            }

        }

    }// End Hooks

}
