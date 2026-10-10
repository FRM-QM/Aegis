package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import com.yubico.yubikit.core.application.CommandState;

/**
 * A CommandState that reports when the authenticator is waiting for the user to touch it and
 * which step of the process the touch is for. Call {@link #cancel()} to abort a pending command.
 */
public class Fido2CommandState extends CommandState {
    public enum Step {
        /** Setting up the connection, before any of the other steps started. */
        CONNECT,
        REGISTER,
        CONFIRM,
        UNLOCK
    }

    public interface Listener {
        /**
         * Called on the thread that communicates with the authenticator, possibly many times per step.
         */
        void onTouchRequired(Step step);
    }

    @Nullable
    private final Listener _listener;
    private volatile Step _step = Step.CONNECT;

    public Fido2CommandState(@Nullable Listener listener) {
        _listener = listener;
    }

    public Step getStep() {
        return _step;
    }

    void setStep(Step step) {
        _step = step;
    }

    @Override
    public void onKeepAliveStatus(byte status) {
        if (status == STATUS_UPNEEDED && _listener != null) {
            _listener.onTouchRequired(_step);
        }
    }
}
