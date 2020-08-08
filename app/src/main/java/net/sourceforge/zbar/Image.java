//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package net.sourceforge.zbar;

public class Image {
    private long peer;
    @SuppressWarnings("unused")
    private Object data;

    private static native void init();

    public Image() {
        this.peer = this.create();
    }

    public Image(int width, int height, String format) {
        this();
        this.setSize(width, height);
        this.setFormat(format);
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

    public native void setFormat(String var1);

    public native int getSequence();

    public native void setSequence(int var1);

    public native int[] getSize();

    public native void setSize(int var1, int var2);

    public native void setSize(int[] var1);

    public native byte[] getData();

    public native void setData(byte[] var1);

    public native void setData(int[] var1);

    static {
        System.loadLibrary("zbarjni");
        init();
    }
}
