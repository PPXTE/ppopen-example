
package com.pingpongx.exampl.tool.sign;


/**
 * 
 */
public class PPApiException extends Exception {

    private static final long serialVersionUID = -238091758285157331L;

    private String            errCode;
    private String            errMsg;

    public PPApiException() {
        super();
    }

    public PPApiException(String message, Throwable cause) {
        super(message, cause);
    }

    public PPApiException(String message) {
        super(message);
    }

    public PPApiException(Throwable cause) {
        super(cause);
    }

    public PPApiException(String errCode, String errMsg) {
        super(errCode + ":" + errMsg);
        this.errCode = errCode;
        this.errMsg = errMsg;
    }

    public String getErrCode() {
        return this.errCode;
    }

    public String getErrMsg() {
        return this.errMsg;
    }

}