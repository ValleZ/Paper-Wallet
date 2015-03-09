package com.d_project.qrcode;

/**
 * @author Kazuhiko Arase
 */
public interface ErrorCorrectLevel {

    public static final int L = 1;

    /**
     * 15%.
     */
    public static final int M = 0;

    /**
     * 25%.
     */
    public static final int Q = 3;

    /**
     * 30%.
     */
    public static final int H = 2;

}
