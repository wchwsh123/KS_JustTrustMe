package just.trust.me;

import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.setObjectField;

import android.annotation.SuppressLint;
import android.util.Log;

import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.HttpParams;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedHelpers;

public class HookUtils {

    /* Helpers */
    // Check for TrustManagerImpl class
    @SuppressLint("PrivateApi")
    protected static boolean hasTrustManagerImpl() {
        try {
            Class.forName("com.android.org.conscrypt.TrustManagerImpl");
        } catch (ClassNotFoundException e) {
            return false;
        }
        return true;
    }


    /**
     * Create a SingleClientConnManager that trusts everyone!
     */
    public static ClientConnectionManager getSCCM() {
        KeyStore trustStore;
        try {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            SSLSocketFactory sf = new TrustAllSSLSocketFactory(trustStore);
            sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            SchemeRegistry registry = new SchemeRegistry();
            registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
            registry.register(new Scheme("https", sf, 443));
            return new SingleClientConnManager(null, registry);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * This function creates a ThreadSafeClientConnManager that trusts everyone!
     */
    public static ClientConnectionManager getTSCCM(HttpParams params) {
        KeyStore trustStore;
        try {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            SSLSocketFactory sf = new TrustAllSSLSocketFactory(trustStore);
            sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            SchemeRegistry registry = new SchemeRegistry();
            registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
            registry.register(new Scheme("https", sf, 443));
            return new ThreadSafeClientConnManager(params, registry);
        } catch (Exception e) {
            return null;
        }
    }

    //This function determines what object we are dealing with.
    public static ClientConnectionManager getCCM(Object o, HttpParams params) {
        String className = o.getClass().getSimpleName();
        if (className.equals("SingleClientConnManager")) {
            return getSCCM();
        } else if (className.equals("ThreadSafeClientConnManager")) {
            return getTSCCM(params);
        }
        return null;
    }

    protected static boolean hasDefaultHTTPClient() {
        try {
            Class.forName("org.apache.http.impl.client.DefaultHttpClient");
        } catch (ClassNotFoundException e) {
            return false;
        }
        return true;
    }

    protected static void processDefaultHttp(String tag, final String currentPackageName) {
        if (!hasDefaultHTTPClient()) {
            return;
        }
        /* Apache Hooks */
        /* external/apache-http/src/org/apache/http/impl/client/DefaultHttpClient.java */
        /* public DefaultHttpClient() */
        if (hasDefaultHTTPClient()) {
            Log.d(tag, String.format("Hooking DefaultHTTPClient for: %s", currentPackageName));
            findAndHookConstructor(DefaultHttpClient.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    setObjectField(param.thisObject, "defaultParams", null);
                    setObjectField(param.thisObject, "connManager", getSCCM());
                }
            });
            /* external/apache-http/src/org/apache/http/impl/client/DefaultHttpClient.java */
            /* public DefaultHttpClient(HttpParams params) */
            Log.d(tag, String.format("Hooking DefaultHTTPClient(HttpParams) for: %s", currentPackageName));
            findAndHookConstructor(DefaultHttpClient.class, HttpParams.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    setObjectField(param.thisObject, "defaultParams", param.args[0]);
                    setObjectField(param.thisObject, "connManager", getSCCM());
                }
            });
            /* external/apache-http/src/org/apache/http/impl/client/DefaultHttpClient.java */
            /* public DefaultHttpClient(ClientConnectionManager conman, HttpParams params) */
            Log.d(tag, String.format("Hooking DefaultHTTPClient(ClientConnectionManager, HttpParams) for: %s", currentPackageName));
            findAndHookConstructor(DefaultHttpClient.class, ClientConnectionManager.class, HttpParams.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    HttpParams params = (HttpParams) param.args[1];
                    setObjectField(param.thisObject, "defaultParams", params);
                    setObjectField(param.thisObject, "connManager", getCCM(param.args[0], params));
                }
            });
        }
    }

    protected static void processXutils(final String tag, ClassLoader classLoader, String currentPackageName) {
        Log.d(tag, String.format("Hooking org.xutils.http.RequestParams.setSslSocketFactory(SSLSocketFactory) (3) for: %s", currentPackageName));
        try {
            classLoader.loadClass("org.xutils.http.RequestParams");
            findAndHookMethod("org.xutils.http.RequestParams", classLoader, "setSslSocketFactory", javax.net.ssl.SSLSocketFactory.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    param.args[0] = getEmptySSLFactory(tag);
                }
            });
            findAndHookMethod("org.xutils.http.RequestParams", classLoader, "setHostnameVerifier", HostnameVerifier.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    param.args[0] = new ImSureItsLegitHostnameVerifier();
                }
            });
        } catch (Exception e) {
            Log.d(tag, String.format("org.xutils.http.RequestParams not found in %s-- not hooking", currentPackageName));
        }
    }

    protected static void processHttpClientAndroidLib(String tag, ClassLoader classLoader, String packageName) {
        /* httpclientandroidlib Hooks */
        /* public final void verify(String host, String[] cns, String[] subjectAlts, boolean strictWithSubDomains) throws SSLException */
        Log.d(tag, String.format("Hooking AbstractVerifier.verify(String, String[], String[], boolean) for: %s", packageName));
        try {
            classLoader.loadClass("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
            findAndHookMethod("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", classLoader, "verify", String.class, String[].class, String[].class, boolean.class, XC_MethodReplacement.DO_NOTHING);
        } catch (ClassNotFoundException e) {
            // pass
            Log.d(tag, String.format("httpclientandroidlib not found in %s-- not hooking", packageName));
        }
    }

    protected static void processOkHttp(String tag, ClassLoader classLoader, String packageName) {
        /* hooking OKHTTP by SQUAREUP */
        /* com/squareup/okhttp/CertificatePinner.java available online @ https://github.com/square/okhttp/blob/master/okhttp/src/main/java/com/squareup/okhttp/CertificatePinner.java */
        /* public void check(String hostname, List<Certificate> peerCertificates) throws SSLPeerUnverifiedException{}*/
        /* Either returns true or a exception so blanket return true */
        /* Tested against version 2.5 */
        Log.d(tag, String.format("Hooking com.squareup.okhttp.CertificatePinner.check(String,List) (2.5) for: %s", packageName));
        try {
            classLoader.loadClass("com.squareup.okhttp.CertificatePinner");
            findAndHookMethod("com.squareup.okhttp.CertificatePinner", classLoader, "check", String.class, List.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam methodHookParam) throws Throwable {
                    return true;
                }
            });
        } catch (ClassNotFoundException e) {
            // pass
            Log.d(tag, String.format("OKHTTP 2.5 not found in %s-- not hooking", packageName));
        }
        //https://github.com/square/okhttp/blob/parent-3.0.1/okhttp/src/main/java/okhttp3/CertificatePinner.java#L144
        Log.d(tag, String.format("Hooking okhttp3.CertificatePinner.check(String,List) (3.x) for: %s", packageName));
        try {
            classLoader.loadClass("okhttp3.CertificatePinner");
            findAndHookMethod("okhttp3.CertificatePinner", classLoader, "check", String.class, List.class, XC_MethodReplacement.DO_NOTHING);
        } catch (ClassNotFoundException e) {
            Log.d(tag, String.format("OKHTTP 3.x not found in %s -- not hooking", packageName));
            // pass
        }
        //https://github.com/square/okhttp/blob/parent-3.0.1/okhttp/src/main/java/okhttp3/internal/tls/OkHostnameVerifier.java
        try {
            classLoader.loadClass("okhttp3.internal.tls.OkHostnameVerifier");
            findAndHookMethod("okhttp3.internal.tls.OkHostnameVerifier", classLoader, "verify", String.class, javax.net.ssl.SSLSession.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam methodHookParam) throws Throwable {
                    return true;
                }
            });
        } catch (ClassNotFoundException e) {
            Log.d(tag, String.format("OKHTTP 3.x not found in %s -- not hooking OkHostnameVerifier.verify(String, SSLSession)", packageName));
            // pass
        }
        //https://github.com/square/okhttp/blob/parent-3.0.1/okhttp/src/main/java/okhttp3/internal/tls/OkHostnameVerifier.java
        try {
            classLoader.loadClass("okhttp3.internal.tls.OkHostnameVerifier");
            findAndHookMethod("okhttp3.internal.tls.OkHostnameVerifier", classLoader, "verify", String.class, java.security.cert.X509Certificate.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam methodHookParam) throws Throwable {
                    return true;
                }
            });
        } catch (ClassNotFoundException e) {
            Log.d(tag, String.format("OKHTTP 3.x not found in %s -- not hooking OkHostnameVerifier.verify(String, X509)(", packageName));
            // pass
        }
        //https://github.com/square/okhttp/blob/okhttp_4.2.x/okhttp/src/main/java/okhttp3/CertificatePinner.kt
        Log.d(tag, String.format("Hooking okhttp3.CertificatePinner.check(String,List) (4.2.0+) for: %s", packageName));
        try {
            classLoader.loadClass("okhttp3.CertificatePinner");
            findAndHookMethod("okhttp3.CertificatePinner", classLoader, "check$okhttp", String.class, "kotlin.jvm.functions.Function0", XC_MethodReplacement.DO_NOTHING);
        } catch (XposedHelpers.ClassNotFoundError | ClassNotFoundException | NoSuchMethodError e) {
            Log.d(tag, String.format("OKHTTP 4.2.0+ (check$okhttp) not found in %s -- not hooking", packageName));
            // pass
        }

        try {
            classLoader.loadClass("okhttp3.CertificatePinner");
            findAndHookMethod("okhttp3.CertificatePinner", classLoader, "check", String.class, List.class, XC_MethodReplacement.DO_NOTHING);
        } catch (XposedHelpers.ClassNotFoundError | ClassNotFoundException | NoSuchMethodError e) {
            Log.d(tag, String.format("OKHTTP 4.2.0+ (check) not found in %s -- not hooking", packageName));
            // pass
        }
    }

    private static javax.net.ssl.SSLSocketFactory getEmptySSLFactory(String tag) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new ImSureItsLegitTrustManager()}, null);
            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Log.e(tag, "[getEmptySSLFactory]", e);
        }
        return null;
    }

    public static final XC_MethodReplacement RETURN_TRUE = new XC_MethodReplacement() {
        protected Object replaceHookedMethod(XC_MethodHook.MethodHookParam params) throws Throwable {
            return true;
        }
    };
}
