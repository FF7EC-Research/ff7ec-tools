package dev.ff7ecpreservation.extension;

import android.widget.Toast;

/**
 * Same as android-patches/extensions/ff7ec's class of the same name (own
 * declaration, not shared - see Ff7ecShimBridge.java's comment for why).
 * Required by android_bridge.cpp's show_toast(), called from
 * install_yaha_hooks() and the first-decode notification - without this
 * class present, that FindClass() call fails, leaving a pending exception
 * that the very next JNI call (GetMethodID on the now-null class) turns
 * into a hard abort ("JNI DETECTED ERROR IN APPLICATION"), exactly the
 * class of crash ../android-patches spent its whole debugging history
 * chasing - this one would just be our own bug instead of the game's.
 */
public final class ToastRunner implements Runnable {
    private final Toast toast;

    public ToastRunner(Toast toast) {
        this.toast = toast;
    }

    @Override
    public void run() {
        toast.show();
    }
}
