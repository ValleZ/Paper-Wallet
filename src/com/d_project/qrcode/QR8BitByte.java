package com.d_project.qrcode;

import java.io.UnsupportedEncodingException;

/**
 * QR8BitByte
 * @author Kazuhiko Arase 
 */
class QR8BitByte extends QRData {
	
	public QR8BitByte(String data) {
		super(Mode.MODE_8BIT_BYTE, data);
	}
	
	public void write(BitBuffer buffer) {

		try {

			byte[] data = getData().getBytes(QRUtil.JIS_ENCODING);

            for (byte aData : data) {
                buffer.put(aData, 8);
            }
			
		} catch(UnsupportedEncodingException e) {
			throw new Error(e.getMessage() );
		}		
	}
	
	public int getLength() {
		try {
			return getData().getBytes(QRUtil.JIS_ENCODING).length;
		} catch(UnsupportedEncodingException e) {
			throw new Error(e.getMessage() );
		}
	}
	
}
