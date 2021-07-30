package com.pingpongx.test;

import com.alibaba.fastjson.JSON;
import com.pingpongx.exampl.tool.sign.PPSignature;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

/**
 * 模仿支付宝客户端请求接口
 */
public class FXClientPostTest extends TestBase {

    String url = "https://dev-openapi.pingpongx.com";
    String appId = "20210722867737075330318336";
    // 平台提供的私钥
    String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCCMZ3szL1DBWMRAe/69F3MsN1XWj2pMEqqOWpgisnGBmsr2RAlPy7VHC4SzxaQC3olNwuSv0srQvSCgd6JSANPibg+V2FWn2fQ3oK2NLPEnWY+1AS1NwTHT8y0orTqJnYuCn732Tz+fXpfIMPMKwwGCUJw6cCrOX05CjY1C+HdjqcA9dQPnmkkFzHcCXtzJjZjD9hN5aSP09T0uPg/fM11tcPWHIQwNqK3C0OuRoBK5MoPFMTFwuzTXFon2YNEV50MBzVnx57kKfJzXn6MXcINesTrBIcda+qs9MZhnXSE7Ax5kj9XsKbV3FPF/32GuDWrSvRneYZ6ZH1bTQwajnvhAgMBAAECggEAP9CIIvib0A0E6OI1OaGrlFggtd9Sl+pGvrcT0CxXCEw/HafwhQE6OFTutGNzILmvbixT7OL8ukDATnPPmySEEuljOJNl76qEnVljYmHkt3ubETKk+Bn2qqcPpH6YBKlDhf+5Ck0d23Ovlo8dyaZT52WEfonk2Uh9e4bo2Qlw9UJyZROFwQih2RVt+ADfplHVGHpJ/yzYhuQwkjSbHaijApLigl5vcWkoOE0MMLoLrPc7FZI69JSeCvJLfmE+mxdSiLcet7yJbhAFOBLzUANEfwh0S9BYEv1rPkunodzKPBL/a1eAXhYcjcBZghl4srF3ktLU5SCuWXCZf6NJ8jN/LQKBgQDEIWgdHLg6AoenKiGrfJIrm2m/RXv6SQg3jgklkt91BoCU6xy36Lt6ZqEDVTVqx9NFxFQE7hEeDNvsmn7uZ2h+tPmUB0fTIGDK9RBjxyaTUV6HC34vus9NOZ/WLzuLdFilGRcp9N2dJ2HVlAZaSWh3ttBg0IRI39HemSoLCTWGHwKBgQCp75i4wOFdE6bmSpmQW66Lf6aGO8CvXv4c8JJHJwat4VqVNfOZLk0S1UEaAlOFfU6sXRJuY5/GqoK0I7Ky67nMaBxGTd1jCuKGyEiL/dE+CJnH0BM1cu/koJEVaufkAVo6Roh9hmloHqHV7Shp3uWm01jQA4UjxCImIdGTlKe9/wKBgQDD7hOSMaSg3vIhPueP5swnIASN/Z4StG6vAQeGL6lnwO0m15FC8A6KAoiLSc4pNCKNKco9eo5DFNmHDfgLteYf3i8NgBByi3/mgNa0triEpt7lzcdraxW4sf5I+7piYAJGPEB1u5bAbh1APbXy8C6amVilvujH3EBOPXhQugxsRQKBgHXqZjuUwwwVzdKwYvwzUdtEOSWdoqdNr+Ae4jFzGARhgbxVknFxGlP+G81TXecbuxKJBngIst5khItA1gem3+bBOxVhhEPsUqEZqpVRCvcTermWXS3SUjl/XQzSgJPKiHQ1axJGyS9RShSqGkfUPeBTeKXmO2VE/DkfcFAKb5a7AoGAd54rjs64DWPrCy0+yLZ7lv5X9/YMaoUVQeMrAG/Eg1beHvoPebcSAXSY1WDRlL55WvlaK0/YqMErM9zZuX407bwnlhnA1eM5R2h27k7AZtE804fuLnr/mdsr9Hb3fIANDijKPpt8tKjDOEz999jUXZpn4KL45L8+h4CYy8ONLkA=";

    @Test
    public void testCard() throws Exception {

        // 公共请求参数
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        params.put("method", "bankcard.card.list");
        params.put("format", "json");
        params.put("charset", "utf-8");
        params.put("sign_type", "RSA2");
        params.put("timestamp", String.valueOf(new Date().getTime()));
        params.put("version", "1.0");

        // 业务参数
        Map<String, Object> bizContent = new HashMap<>();

        params.put("biz_content", JSON.toJSONString(bizContent));
        String content = PPSignature.getSignContent(params);
        String sign = PPSignature.rsa256Sign(content, privateKey, "utf-8");
        params.put("sign", sign);

        System.out.println("----------- 请求信息 -----------");
        System.out.println("请求参数：" + buildParamQuery(params));
        System.out.println("商户秘钥：" + privateKey);
        System.out.println("待签名内容：" + content);
        System.out.println("签名(sign)：" + sign);
        System.out.println("URL参数：" + buildUrlQuery(params));

        System.out.println("----------- 返回结果 -----------");
        String responseData = get(url, params);// 发送请求
        System.out.println(responseData);
    }


}
