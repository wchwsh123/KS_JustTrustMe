package just.trust.me;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Main implements IXposedHookLoadPackage {

    //    private final HookLoader hookLoader = new OriginHookLoader();
    private final HookLoader hookLoader = new V4HookLoader();

    @Override
    public void handleLoadPackage(LoadPackageParam loadPackageParam) throws Throwable {
        hookLoader.handleLoadPackage(loadPackageParam);
    }
}
