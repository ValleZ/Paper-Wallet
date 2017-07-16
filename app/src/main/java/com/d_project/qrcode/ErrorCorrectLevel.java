package com.d_project.qrcode;

/**
 * @author Kazuhiko Arase
 */
public interface ErrorCorrectLevel {

    int L = 1;

    /**
     * 15%.
     */
    int M = 0;

    /**
     * 25%.
     */
    int Q = 3;

    /**
     * 30%.
     */
    int H = 2;

}
