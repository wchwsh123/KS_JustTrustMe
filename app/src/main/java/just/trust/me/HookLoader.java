package just.trust.me;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

public interface HookLoader {

    void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) throws Throwable;

}
