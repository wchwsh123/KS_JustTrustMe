package just.trust.me;

import android.annotation.SuppressLint;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class ImSureItsLegitHostnameVerifier implements HostnameVerifier {

    @SuppressLint("BadHostnameVerifier")
    public boolean verify(String paramString, SSLSession paramSSLSession) {
        return true;
    }
}