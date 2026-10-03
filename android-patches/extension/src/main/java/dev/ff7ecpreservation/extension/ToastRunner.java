package dev.ff7ecpreservation.extension;

import android.widget.Toast;

/**
 * Trivial Runnable wrapping a pre-built Toast, so native code can show it on
 * the main thread via {@code new Handler(Looper.getMainLooper()).post(...)}
 * without needing its own anonymous-class machinery over JNI.
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
