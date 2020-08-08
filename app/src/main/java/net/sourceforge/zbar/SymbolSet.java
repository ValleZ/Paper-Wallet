//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package net.sourceforge.zbar;

import android.support.annotation.NonNull;

import java.util.AbstractCollection;
import java.util.Iterator;

public class SymbolSet extends AbstractCollection<Symbol> {
    private long peer;

    private static native void init();

    SymbolSet(long peer) {
        this.peer = peer;
    }

    protected void finalize() {
        this.destroy();
    }

    public synchronized void destroy() {
        if (this.peer != 0L) {
            this.destroy(this.peer);
            this.peer = 0L;
        }

    }

    private native void destroy(long var1);

    @NonNull
    public Iterator<Symbol> iterator() {
        long sym = this.firstSymbol(this.peer);
        if (sym == 0L) return new SymbolIterator(null);
        return new SymbolIterator(new Symbol(sym));
    }

    public native int size();

    private native long firstSymbol(long var1);

    static {
        System.loadLibrary("zbarjni");
        init();
    }
}
