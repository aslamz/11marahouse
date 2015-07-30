package com.tinizine.azoomee.auth;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

public class AZServletInputStream extends ServletInputStream {

	private static final int EOL = -1;
	private InputStream inputStream;
	private ReadListener readListener;
	private boolean finished;

	public AZServletInputStream(InputStream is) {
		this.inputStream = is;
	}
	
	@Override
	public boolean isFinished() {
		return this.finished;
	}

	@Override
	public boolean isReady() {
		return !this.finished;
	}

	@Override
	public void setReadListener(ReadListener readListener) {

		this.readListener = readListener;
		if(isReady()) {
			try {
				this.readListener.onDataAvailable();
			} catch(IOException e) {
				this.readListener.onError(e);
			}
		}

	}

	@Override
	public int read() throws IOException {
		int currentByte = inputStream.read();
		if(currentByte == EOL) {
			finished = true;
			if (this.readListener != null)
				this.readListener.onAllDataRead();
		}
		return currentByte;
	}

}
