//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package net.sourceforge.zbar;

public class Symbol {
    private long peer;
    @SuppressWarnings("unused")
    private int type;

    private static native void init();

    Symbol(long peer) {
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

    public native String getData();

    native long next();

    static {
        System.loadLibrary("zbarjni");
        init();
    }
}
