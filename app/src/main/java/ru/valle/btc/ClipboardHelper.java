/*
 The MIT License (MIT)

 Copyright (c) 2013 Valentin Konovalov

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.*/
package ru.valle.btc;

import android.annotation.TargetApi;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;

import java.util.HashMap;

@SuppressWarnings("WeakerAccess")
@TargetApi(Build.VERSION_CODES.HONEYCOMB)
public class ClipboardHelper {

    private final ClipboardManager clipboard;
    private final HashMap<Runnable, ClipboardManager.OnPrimaryClipChangedListener> listeners;

    public ClipboardHelper(Context context) {
        clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        listeners = new HashMap<>();
    }

    public void copyTextToClipboard(String label, String text) {
        ClipData clip = ClipData.newPlainText(label, text);
        clipboard.setPrimaryClip(clip);
    }

    public CharSequence getTextInClipboard() {
        ClipData clipData = clipboard.getPrimaryClip();
        if (clipData == null || clipData.getItemCount() == 0) {
            return null;
        }
        ClipData.Item item = clipData.getItemAt(0);
        return item.getText();
    }

    public boolean hasTextInClipboard() {
        if (clipboard.hasPrimaryClip()) {
            ClipDescription desc = clipboard.getPrimaryClipDescription();
            if (desc != null && (desc.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN) || desc.hasMimeType(ClipDescription.MIMETYPE_TEXT_HTML))) {
                ClipData clip = clipboard.getPrimaryClip();
                if (clip != null && clip.getItemCount() > 0) {
                    ClipData.Item item = clip.getItemAt(0);
                    return item != null && !TextUtils.isEmpty(item.toString());
                }
            }
        }
        return false;
    }

    public void runOnClipboardChange(final Runnable runnable) {
        if (runnable != null) {
            ClipboardManager.OnPrimaryClipChangedListener realListener = runnable::run;
            listeners.put(runnable, realListener);
            clipboard.addPrimaryClipChangedListener(realListener);
        }
    }

    public void removeClipboardListener(Runnable runnable) {
        if (runnable != null && listeners.containsKey(runnable)) {
            clipboard.removePrimaryClipChangedListener(listeners.get(runnable));
        }
    }
}
