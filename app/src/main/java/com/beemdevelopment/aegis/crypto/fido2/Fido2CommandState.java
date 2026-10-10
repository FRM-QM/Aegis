package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import com.yubico.yubikit.core.application.CommandState;

/**
 * A CommandState that reports when the user has to touch the authenticator and which step of the
 * process the touch is for. Call {@link #cancel()} to abort a pending command.
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
         *
         * @param reported Whether the authenticator reported that it's waiting for a touch. If false, a
         *                 command that requires a touch is about to be sent. Over USB, that's the only
         *                 reliable signal, because not every authenticator reports that it's waiting.
         *                 Over NFC, holding the authenticator against the device already counts as a
         *                 touch, so the user only has to do something else if the authenticator says so.
         */
        void onTouchRequired(Step step, boolean reported);
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

    /**
     * Called right before a command is sent that requires the user to touch the authenticator.
     */
    void onTouchCommand() {
        if (_listener != null) {
            _listener.onTouchRequired(_step, false);
        }
    }

    @Override
    public void onKeepAliveStatus(byte status) {
        if (status == STATUS_UPNEEDED && _listener != null) {
            _listener.onTouchRequired(_step, true);
        }
    }
}
