package com.d_project.qrcode;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Kazuhiko Arase
 */
@SuppressWarnings("WeakerAccess")
public class QRCode {

    private static final int PAD0 = 0xEC;

    private static final int PAD1 = 0x11;

    private int typeNumber;

    private Boolean[][] modules;

    private int moduleCount;

    private int errorCorrectLevel;

    private final List<QRData> qrDataList;

    private QRCode() {
        this.typeNumber = 1;
        this.errorCorrectLevel = ErrorCorrectLevel.H;
        this.qrDataList = new ArrayList<>(1);
    }

    public void setTypeNumber(int typeNumber) {
        this.typeNumber = typeNumber;
    }

    public void setErrorCorrectLevel(int errorCorrectLevel) {
        this.errorCorrectLevel = errorCorrectLevel;
    }

    public void addData(String data, int mode) {

        switch (mode) {

            case Mode.MODE_NUMBER:
                addData(new QRNumber(data));
                break;

            case Mode.MODE_ALPHA_NUM:
                addData(new QRAlphaNum(data));
                break;

            case Mode.MODE_8BIT_BYTE:
                addData(new QR8BitByte(data));
                break;

            default:
                throw new IllegalArgumentException("mode:" + mode);
        }
    }

    private void addData(QRData qrData) {
        qrDataList.add(qrData);
    }

    private QRData getData() {
        return qrDataList.get(0);
    }

    public boolean isDark(int row, int col) {
        if (modules[row][col] != null) {
            return modules[row][col];
        } else {
            return false;
        }
    }

    public int getModuleCount() {
        return moduleCount;
    }

    public void make() {
        make(false, getBestMaskPattern());
    }

    private int getBestMaskPattern() {

        int minLostPoint = 0;
        int pattern = 0;

        for (int i = 0; i < 8; i++) {

            make(true, i);

            int lostPoint = QRUtil.getLostPoint(this);

            if (i == 0 || minLostPoint > lostPoint) {
                minLostPoint = lostPoint;
                pattern = i;
            }
        }

        return pattern;
    }

    /**
     *
     */
    private void make(boolean test, int maskPattern) {

        moduleCount = typeNumber * 4 + 17;
        modules = new Boolean[moduleCount][moduleCount];

        setupPositionProbePattern(0, 0);
        setupPositionProbePattern(moduleCount - 7, 0);
        setupPositionProbePattern(0, moduleCount - 7);

        setupPositionAdjustPattern();
        setupTimingPattern();

        setupTypeInfo(test, maskPattern);

        if (typeNumber >= 7) {
            setupTypeNumber(test);
        }

        QRData[] dataArray = qrDataList.toArray(new QRData[qrDataList.size()]);

        byte[] data = createData(typeNumber, errorCorrectLevel, dataArray);

        mapData(data, maskPattern);
    }

    private void mapData(byte[] data, int maskPattern) {

        int inc = -1;
        int row = moduleCount - 1;
        int bitIndex = 7;
        int byteIndex = 0;

        for (int col = moduleCount - 1; col > 0; col -= 2) {

            if (col == 6) col--;

            while (true) {

                for (int c = 0; c < 2; c++) {

                    if (modules[row][col - c] == null) {

                        boolean dark = false;

                        if (byteIndex < data.length) {
                            dark = (((data[byteIndex] >>> bitIndex) & 1) == 1);
                        }

                        boolean mask = QRUtil.getMask(maskPattern, row, col - c);

                        if (mask) {
                            dark = !dark;
                        }

                        modules[row][col - c] = dark;
                        bitIndex--;

                        if (bitIndex == -1) {
                            byteIndex++;
                            bitIndex = 7;
                        }
                    }
                }

                row += inc;

                if (row < 0 || moduleCount <= row) {
                    row -= inc;
                    inc = -inc;
                    break;
                }
            }
        }

    }

    private void setupPositionAdjustPattern() {

        int[] pos = QRUtil.getPatternPosition(typeNumber);

        for (int row : pos) {

            for (int col : pos) {
                if (modules[row][col] != null) {
                    continue;
                }

                for (int r = -2; r <= 2; r++) {
                    for (int c = -2; c <= 2; c++) {
                        modules[row + r][col + c] = r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0);
                    }
                }

            }
        }
    }

    private void setupPositionProbePattern(int row, int col) {

        for (int r = -1; r <= 7; r++) {

            for (int c = -1; c <= 7; c++) {

                if (row + r <= -1 || moduleCount <= row + r
                        || col + c <= -1 || moduleCount <= col + c) {
                    continue;
                }

                modules[row + r][col + c] = (0 <= r && r <= 6 && (c == 0 || c == 6))
                        || (0 <= c && c <= 6 && (r == 0 || r == 6))
                        || (2 <= r && r <= 4 && 2 <= c && c <= 4);
            }
        }
    }


    private void setupTimingPattern() {
        for (int r = 8; r < moduleCount - 8; r++) {
            if (modules[r][6] != null) {
                continue;
            }
            modules[r][6] = r % 2 == 0;
        }
        for (int c = 8; c < moduleCount - 8; c++) {
            if (modules[6][c] != null) {
                continue;
            }
            modules[6][c] = c % 2 == 0;
        }
    }

    private void setupTypeNumber(boolean test) {

        int bits = QRUtil.getBCHTypeNumber(typeNumber);

        for (int i = 0; i < 18; i++) {
            Boolean mod = !test && ((bits >> i) & 1) == 1;
            modules[i / 3][i % 3 + moduleCount - 8 - 3] = mod;
        }

        for (int i = 0; i < 18; i++) {
            Boolean mod = !test && ((bits >> i) & 1) == 1;
            modules[i % 3 + moduleCount - 8 - 3][i / 3] = mod;
        }
    }

    private void setupTypeInfo(boolean test, int maskPattern) {

        int data = (errorCorrectLevel << 3) | maskPattern;
        int bits = QRUtil.getBCHTypeInfo(data);

        for (int i = 0; i < 15; i++) {

            Boolean mod = !test && ((bits >> i) & 1) == 1;

            if (i < 6) {
                modules[i][8] = mod;
            } else if (i < 8) {
                modules[i + 1][8] = mod;
            } else {
                modules[moduleCount - 15 + i][8] = mod;
            }
        }

        for (int i = 0; i < 15; i++) {

            Boolean mod = !test && ((bits >> i) & 1) == 1;

            if (i < 8) {
                modules[8][moduleCount - i - 1] = mod;
            } else if (i < 9) {
                modules[8][15 - i - 1 + 1] = mod;
            } else {
                modules[8][15 - i - 1] = mod;
            }
        }

        modules[moduleCount - 8][8] = !test;

    }

    public static byte[] createData(int typeNumber, int errorCorrectLevel, QRData[] dataArray) {

        RSBlock[] rsBlocks = RSBlock.getRSBlocks(typeNumber, errorCorrectLevel);

        BitBuffer buffer = new BitBuffer();

        for (QRData data : dataArray) {
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), data.getLengthInBits(typeNumber));
            data.write(buffer);
        }

        int totalDataCount = 0;
        for (RSBlock rsBlock : rsBlocks) {
            totalDataCount += rsBlock.getDataCount();
        }

        if (buffer.getLengthInBits() > totalDataCount * 8) {
            throw new IllegalArgumentException("code length overflow. ("
                    + buffer.getLengthInBits()
                    + ">"
                    + totalDataCount * 8
                    + "). typeNumber should be increased.");
        }

        if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
            buffer.put(0, 4);
        }

        // padding
        while (buffer.getLengthInBits() % 8 != 0) {
            buffer.put(false);
        }

        // padding
        while (true) {

            if (buffer.getLengthInBits() >= totalDataCount * 8) {
                break;
            }
            buffer.put(PAD0, 8);

            if (buffer.getLengthInBits() >= totalDataCount * 8) {
                break;
            }
            buffer.put(PAD1, 8);
        }

        return createBytes(buffer, rsBlocks);
    }

    private static byte[] createBytes(BitBuffer buffer, RSBlock[] rsBlocks) {

        int offset = 0;

        int maxDcCount = 0;
        int maxEcCount = 0;

        int[][] dcdata = new int[rsBlocks.length][];
        int[][] ecdata = new int[rsBlocks.length][];

        for (int r = 0; r < rsBlocks.length; r++) {

            int dcCount = rsBlocks[r].getDataCount();
            int ecCount = rsBlocks[r].getTotalCount() - dcCount;

            maxDcCount = Math.max(maxDcCount, dcCount);
            maxEcCount = Math.max(maxEcCount, ecCount);

            dcdata[r] = new int[dcCount];
            for (int i = 0; i < dcdata[r].length; i++) {
                dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
            }
            offset += dcCount;

            Polynomial rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
            Polynomial rawPoly = new Polynomial(dcdata[r], rsPoly.getLength() - 1);

            Polynomial modPoly = rawPoly.mod(rsPoly);
            ecdata[r] = new int[rsPoly.getLength() - 1];
            for (int i = 0; i < ecdata[r].length; i++) {
                int modIndex = i + modPoly.getLength() - ecdata[r].length;
                ecdata[r][i] = (modIndex >= 0) ? modPoly.get(modIndex) : 0;
            }

        }

        int totalCodeCount = 0;
        for (RSBlock rsBlock : rsBlocks) {
            totalCodeCount += rsBlock.getTotalCount();
        }

        byte[] data = new byte[totalCodeCount];

        int index = 0;

        for (int i = 0; i < maxDcCount; i++) {
            for (int r = 0; r < rsBlocks.length; r++) {
                if (i < dcdata[r].length) {
                    data[index++] = (byte) dcdata[r][i];
                }
            }
        }

        for (int i = 0; i < maxEcCount; i++) {
            for (int r = 0; r < rsBlocks.length; r++) {
                if (i < ecdata[r].length) {
                    data[index++] = (byte) ecdata[r][i];
                }
            }
        }

        return data;

    }

    @SuppressWarnings("SameParameterValue")
    public static QRCode getMinimumQRCode(String data, int errorCorrectLevel) {

        int mode = QRUtil.getMode(data);

        QRCode qr = new QRCode();
        qr.setErrorCorrectLevel(errorCorrectLevel);
        qr.addData(data, mode);

        int length = qr.getData().getLength();

        for (int typeNumber = 1; typeNumber <= 10; typeNumber++) {
            if (length <= QRUtil.getMaxLength(typeNumber, mode, errorCorrectLevel)) {
                qr.setTypeNumber(typeNumber);
                break;
            }
        }

        qr.make();

        return qr;
    }

    public Bitmap createImage(int maxImageSizePixels) {
        int moduleCount = getModuleCount();
        int cellSize = maxImageSizePixels / moduleCount;
        int imageSize = moduleCount * cellSize;
        Bitmap bmp = Bitmap.createBitmap(imageSize, imageSize, Bitmap.Config.RGB_565);
        Canvas c = new Canvas(bmp);
        Paint lightPaint = new Paint();
        lightPaint.setStyle(Paint.Style.FILL);
        lightPaint.setARGB(0xFF, 0xFF, 0xFF, 0xFF);
        lightPaint.setAntiAlias(false);
        c.drawRect(0, 0, c.getWidth(), c.getHeight(), lightPaint);
        Paint darkPaint = new Paint();
        darkPaint.setStyle(Paint.Style.FILL);
        darkPaint.setARGB(0xFF, 0, 0, 0);
        darkPaint.setAntiAlias(false);
        Rect rect = new Rect();
        for (int col = 0; col < moduleCount; col++) {
            for (int row = 0; row < moduleCount; row++) {
                if (isDark(row, col)) {
                    int x = col * cellSize;
                    int y = row * cellSize;
                    rect.set(x, y, x + cellSize, y + cellSize);
                    c.drawRect(rect, darkPaint);
                }
            }
        }
        return bmp;
    }

}
