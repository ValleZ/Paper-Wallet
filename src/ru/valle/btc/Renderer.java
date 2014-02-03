/**
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

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.AsyncTask;
import android.support.v4.print.PrintHelper;
import android.text.TextPaint;
import android.widget.ImageView;
import com.d_project.qrcode.ErrorCorrectLevel;
import com.d_project.qrcode.QRCode;

import java.util.ArrayList;

public class Renderer {
    static void print(final Activity context, final String label, final String data) {
        new AsyncTask<Void, Void, Bitmap>() {

            @Override
            protected Bitmap doInBackground(Void... params) {
                QRCode qr = QRCode.getMinimumQRCode(data, ErrorCorrectLevel.M);
                TextPaint textPaint = new TextPaint();
                textPaint.setAntiAlias(true);
                textPaint.setColor(0xFF000000);
                final int bitmapMargin = 18;
                final int textHeight = 28;
                textPaint.setTextSize(textHeight);
                textPaint.setTextAlign(Paint.Align.CENTER);
                final int qrCodePadding = (int) (textPaint.descent() * 2);
                Rect bounds = new Rect();
                textPaint.getTextBounds(data, 0, data.length(), bounds);
                int textWidth = getTextWidth(data, textPaint);
                ArrayList<String> labelLinesRelaxed = wrap(label, textWidth, false, textPaint);
                for (String titleLine : labelLinesRelaxed) {
                    textWidth = Math.max(textWidth, getTextWidth(titleLine, textPaint));
                }
                Bitmap qrCodeBitmap = qr.createImage(textWidth, 0);
                ArrayList<String> labelLines = wrap(label, textWidth, true, textPaint);
                Bitmap bmp = Bitmap.createBitmap(textWidth + bitmapMargin * 2, qrCodeBitmap.getHeight() + textHeight * (labelLines.size() + 1) + qrCodePadding * 2 + bitmapMargin * 2, Bitmap.Config.RGB_565);
                Canvas canvas = new Canvas(bmp);
                Paint lightPaint = new Paint();
                lightPaint.setStyle(Paint.Style.FILL);
                lightPaint.setARGB(0xFF, 0xFF, 0xFF, 0xFF);
                lightPaint.setAntiAlias(false);
                canvas.drawRect(0, 0, canvas.getWidth(), canvas.getHeight(), lightPaint);
                int y = (int) (bitmapMargin - textPaint.ascent());
                for (int i = 0; i < labelLines.size(); i++) {
                    canvas.drawText(labelLines.get(i), bmp.getWidth() / 2, y + i * textHeight, textPaint);
                }
                y = bitmapMargin + labelLines.size() * textHeight + qrCodePadding;
                Paint qrCodePaint = new Paint();
                qrCodePaint.setAntiAlias(false);
                qrCodePaint.setDither(false);
                canvas.drawBitmap(qrCodeBitmap, (bmp.getWidth() - qrCodeBitmap.getWidth()) / 2, y, qrCodePaint);
                y += qrCodeBitmap.getHeight() + qrCodePadding - textPaint.ascent();
                canvas.drawText(data, bmp.getWidth() / 2, y, textPaint);
                return bmp;
            }

            @Override
            protected void onPostExecute(final Bitmap bitmap) {
                if (bitmap != null) {
//DEBUG
//                    AlertDialog.Builder builder = new AlertDialog.Builder(context);
//                    ImageView view = (ImageView) context.getLayoutInflater().inflate(R.layout.image_view, null);
//                    if (view != null) {
//                        view.setImageBitmap(bitmap);
//                        builder.setView(view);
//                    }
//                    builder.setPositiveButton(android.R.string.ok, null);
//                    builder.show();

                    PrintHelper printHelper = new PrintHelper(context);
                    printHelper.setScaleMode(PrintHelper.SCALE_MODE_FIT);
                    printHelper.printBitmap(label, bitmap);
                }

            }
        }.execute();
    }

    private static int getTextWidth(String s, Paint paint) {
        Rect bounds = new Rect();
        paint.getTextBounds(s, 0, s.length(), bounds);
        return bounds.right - bounds.left;
    }

    public static ArrayList<String> wrap(String txt, int maxWidth, boolean mustFit, Paint paint) {
        int pos = 0;
        int start = pos;
        ArrayList<String> lines = new ArrayList<String>();
        while (true) {
            int i = pos;
            if (txt == null) txt = "";
            int len = txt.length();
            if (pos >= len) {
                break;
            }
            int startForLineBreak = pos;
            while (true) {
                while (i < len && txt.charAt(i) != ' ' && txt.charAt(i) != '\n') {
                    i++;
                }
                int w = getTextWidth(txt.substring(startForLineBreak, i), paint);
                if (pos == startForLineBreak) {
                    if (w > maxWidth) {
                        if (mustFit) {
                            do {
                                i--;
                            } while (getTextWidth(txt.substring(startForLineBreak, i), paint) > maxWidth);
                        }
                        pos = i;
                        break;
                    }
                }
                if (w <= maxWidth) {
                    pos = i;
                    if (pos >= len)
                        break;
                }
                if (w > maxWidth || i >= len || txt.charAt(i) == '\n') {
                    break;
                }
                i++;
            }
            int nextBreak = pos >= len ? len : ++pos;

            if (nextBreak >= txt.length()) {
                lines.add(txt.substring(start, txt.length()));
            } else {
                char c = txt.charAt(nextBreak - 1);
                if ((c == ' ') || (c == '\n')) {
                    if (nextBreak - 2 < start) {
                        lines.add("");
                    } else {
                        lines.add(txt.substring(start, nextBreak - 1));
                    }
                } else {
                    lines.add(txt.substring(start, nextBreak));
                }
            }
            start = pos;
        }
        return lines;
    }

}
