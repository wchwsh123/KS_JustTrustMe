package just.trust.me;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

import android.content.Context;
import android.net.http.SslError;
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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class V4HookLoader implements HookLoader {

    private static final String TAG = "V4HookLoader";

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam localPackageParam) throws Throwable {
        final String currentPackageName = localPackageParam.packageName;
        //=========================== Apache ===========================
        //FIXME 这里少了对于DefaultHttpClient的处理，添加一下
        HookUtils.processDefaultHttp(TAG, currentPackageName);
        /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
        /* public SSLSocketFactory( ... ) */
        Log.d(TAG, String.format("Hooking SSLSocketFactory(String, KeyStore, String, KeyStore) for: %s", currentPackageName));
        try {
            XposedHelpers.findAndHookConstructor(SSLSocketFactory.class, String.class, KeyStore.class, String.class, KeyStore.class, SecureRandom.class, HostNameResolver.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    final String algorithm = (String) param.args[0];
                    final KeyStore keystore = (KeyStore) param.args[1];
                    final String keystorePassword = (String) param.args[2];
                    SecureRandom localSecureRandom = (SecureRandom) param.args[4];
                    final KeyManager[] keyManagers;
                    if (keystore != null) {
                        keyManagers = (KeyManager[]) XposedHelpers.callStaticMethod(SSLSocketFactory.class, "createKeyManagers", new Object[]{keystore, keystorePassword});
                    } else {
                        keyManagers = null;
                    }
                    XposedHelpers.setObjectField(param.thisObject, "sslcontext", SSLContext.getInstance(algorithm));
                    XposedHelpers.callMethod(XposedHelpers.getObjectField(param.thisObject, "sslcontext"), "init", keyManagers, new TrustManager[]{new ImSureItsLegitTrustManager()}, localSecureRandom);
                    XposedHelpers.setObjectField(param.thisObject, "socketfactory", XposedHelpers.callMethod(XposedHelpers.getObjectField(param.thisObject, "sslcontext"), "getSocketFactory"));
                }
            });
            Log.d(TAG, String.format("Hooking static SSLSocketFactory(String, KeyStore, String, KeyStore) for: %s", currentPackageName));
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", localPackageParam.classLoader, "getSocketFactory", new XC_MethodReplacement() {
                protected Object replaceHookedMethod(XC_MethodHook.MethodHookParam paramAnonymousMethodHookParam) throws Throwable {
                    return XposedHelpers.newInstance(SSLSocketFactory.class);
                }
            });
        } catch (NoClassDefFoundError e) {
            Log.d(TAG, String.format("NoClassDefFoundError SSLSocketFactory HostNameResolver for: %s", currentPackageName));
        }
        /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
        /* public boolean isSecure(Socket) */
        Log.d(TAG, String.format("Hooking SSLSocketFactory(Socket) for: %s", currentPackageName));
        //FIXME 不一样
        XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", localPackageParam.classLoader, "isSecure", Socket.class, HookUtils.RETURN_TRUE);
        //=========================== JSSE ===========================
        /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
        /* public final TrustManager[] getTrustManager() */
        Log.d(TAG, String.format("Hooking TrustManagerFactory.getTrustManagers() for: %s", currentPackageName));
        XposedHelpers.findAndHookMethod("javax.net.ssl.TrustManagerFactory", localPackageParam.classLoader, "getTrustManagers", new XC_MethodHook() {
            protected void afterHookedMethod(XC_MethodHook.MethodHookParam param) throws Throwable {
                if (HookUtils.hasTrustManagerImpl()) {
                    Class<?> localClass = XposedHelpers.findClass("com.android.org.conscrypt.TrustManagerImpl", localPackageParam.classLoader);
                    TrustManager[] arrayOfTrustManager = (TrustManager[]) param.getResult();
                    if ((arrayOfTrustManager.length > 0) && (localClass.isInstance(arrayOfTrustManager[0]))) {
                        return;
                    }
                }
                param.setResult(new TrustManager[]{new ImSureItsLegitTrustManager()});
            }
        });
        //=========================== HttpsURLConnection ===========================
        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setDefaultHostnameVerifier(HostnameVerifier) */
        Log.d(TAG, String.format("Hooking HttpsURLConnection.setDefaultHostnameVerifier for: %s", currentPackageName));
        XposedHelpers.findAndHookMethod("javax.net.ssl.HttpsURLConnection", localPackageParam.classLoader, "setDefaultHostnameVerifier", HostnameVerifier.class, XC_MethodReplacement.DO_NOTHING);
        Log.d(TAG, String.format("Hooking HttpsURLConnection.setSSLSocketFactory for: %s", currentPackageName));
        XposedHelpers.findAndHookMethod("javax.net.ssl.HttpsURLConnection", localPackageParam.classLoader, "setSSLSocketFactory", javax.net.ssl.SSLSocketFactory.class, XC_MethodReplacement.DO_NOTHING);
        Log.d(TAG, String.format("Hooking HttpsURLConnection.setHostnameVerifier for: %s", currentPackageName));
        XposedHelpers.findAndHookMethod("javax.net.ssl.HttpsURLConnection", localPackageParam.classLoader, "setHostnameVerifier", HostnameVerifier.class, XC_MethodReplacement.DO_NOTHING);
        //=========================== WebView Hooks ===========================
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        Log.d(TAG, String.format("Hooking WebViewClient.onReceivedSslError(WebView, SslErrorHandler, SslError) for: %s", currentPackageName));
        XposedHelpers.findAndHookMethod("android.webkit.WebViewClient", localPackageParam.classLoader, "onReceivedSslError", WebView.class, SslErrorHandler.class, SslError.class, new XC_MethodReplacement() {
            protected Object replaceHookedMethod(XC_MethodHook.MethodHookParam paramAnonymousMethodHookParam) throws Throwable {
                ((SslErrorHandler) paramAnonymousMethodHookParam.args[1]).proceed();
                return null;
            }
        });
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedError(WebView, int, String, String) */
        Log.d(TAG, String.format("Hooking WebViewClient.onReceivedSslError(WebView, int, string, string) for: %s", currentPackageName));
        XposedHelpers.findAndHookMethod("android.webkit.WebViewClient", localPackageParam.classLoader, "onReceivedError", WebView.class, Integer.TYPE, String.class, String.class, XC_MethodReplacement.DO_NOTHING);
        //=========================== SSLContext ===========================
        XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", localPackageParam.classLoader, "init", KeyManager[].class, TrustManager[].class, SecureRandom.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                param.args[0] = null;
                param.args[1] = new TrustManager[]{new ImSureItsLegitTrustManager()};
                param.args[2] = null;
            }
        });
        //=========================== Application ===========================
        XposedHelpers.findAndHookMethod("android.app.Application", localPackageParam.classLoader, "attach", Context.class, new XC_MethodHook() {
            protected void afterHookedMethod(XC_MethodHook.MethodHookParam param) throws Throwable {
                final Context context = (Context) param.args[0];
                HookUtils.processOkHttp(TAG, context.getClassLoader(), currentPackageName);
                HookUtils.processHttpClientAndroidLib(TAG, context.getClassLoader(), currentPackageName);
                HookUtils.processXutils(TAG, context.getClassLoader(), currentPackageName);
            }
        });
        //=========================== TrustManagerImpl ===========================
        /* Only for newer devices should we try to hook TrustManagerImpl */
        if (HookUtils.hasTrustManagerImpl()) {
            /* TrustManagerImpl Hooks */
            /* external/conscrypt/src/platform/java/org/conscrypt/TrustManagerImpl.java */
            Log.d(TAG, String.format("Hooking com.android.org.conscrypt.TrustManagerImpl for: %s", currentPackageName));
            /* public void checkServerTrusted(X509Certificate[] chain, String authType) */
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", localPackageParam.classLoader, "checkServerTrusted", X509Certificate[].class, String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return 0;
                }
            });
            /* public void checkServerTrusted(X509Certificate[] chain, String authType) */
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", localPackageParam.classLoader, "checkServerTrusted", X509Certificate[].class, String.class, String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return new ArrayList<>();
                }
            });
            /* public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host) throws CertificateException */
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", localPackageParam.classLoader, "checkServerTrusted", X509Certificate[].class, String.class, SSLSession.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return new ArrayList<>();
                }
            });
            //FIXME 没有这两段，这里补充下
            try {
                findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", localPackageParam.classLoader, "checkTrusted", X509Certificate[].class, String.class, SSLSession.class, SSLParameters.class, boolean.class, new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return new ArrayList<>();
                    }
                });
                findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", localPackageParam.classLoader, "checkTrusted", X509Certificate[].class, byte[].class, byte[].class, String.class, String.class, boolean.class, new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return new ArrayList<>();
                    }
                });
            } catch (NoSuchMethodError e) {
                //
            }
        }

    }

}
