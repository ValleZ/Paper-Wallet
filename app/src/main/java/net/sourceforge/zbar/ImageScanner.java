//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package net.sourceforge.zbar;

public class ImageScanner {
    private long peer = this.create();

    private static native void init();

    public ImageScanner() {
    }

    private native long create();

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

    public native void setConfig(int var1, int var2, int var3) throws IllegalArgumentException;

    public SymbolSet getResults() {
        return new SymbolSet(this.getResults(this.peer));
    }

    private native long getResults(long var1);

    public native int scanImage(Image var1);

    static {
        System.loadLibrary("zbarjni");
        init();
    }
}
