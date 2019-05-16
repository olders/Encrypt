package des_crypt;
import java.io.IOException;  
import java.security.SecureRandom;  
import javax.crypto.Cipher;  
import javax.crypto.SecretKey;  
import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.DESKeySpec;  
import sun.misc.BASE64Decoder;  
import sun.misc.BASE64Encoder;  

public class des_one {
	   private byte[] desKey; 
	   
	    public des_one(String desKey) {  
	        this.desKey = desKey.getBytes();  
	    }  
	  
	    public byte[] desEncrypt(byte[] plainText) throws Exception {  
	        SecureRandom sr = new SecureRandom();  
	        byte rawKeyData[] = desKey;  
	        DESKeySpec dks = new DESKeySpec(rawKeyData);  
	        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");  
	        SecretKey key = keyFactory.generateSecret(dks);  
	        Cipher cipher = Cipher.getInstance("DES");  
	        cipher.init(Cipher.ENCRYPT_MODE, key, sr);  
	        byte data[] = plainText;  
	        byte encryptedData[] = cipher.doFinal(data);  
	        return encryptedData;  
	    }  
	  
	    public byte[] desDecrypt(byte[] encryptText) throws Exception {  
	        SecureRandom sr = new SecureRandom();  
	        byte rawKeyData[] = desKey;  
	        DESKeySpec dks = new DESKeySpec(rawKeyData);  
	        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");  
	        SecretKey key = keyFactory.generateSecret(dks);  
	        Cipher cipher = Cipher.getInstance("DES");  
	        cipher.init(Cipher.DECRYPT_MODE, key, sr);  
	        byte encryptedData[] = encryptText;  
	        byte decryptedData[] = cipher.doFinal(encryptedData);  
	        return decryptedData;  
	    }  
	  
	    public String encrypt(String input) throws Exception {  
	        return base64Encode(desEncrypt(input.getBytes()));  
	    }  
	  
	    public String decrypt(String input) throws Exception {  
	        byte[] result = base64Decode(input);  
	        return new String(desDecrypt(result));  
	    }  
	  
	    public static String base64Encode(byte[] s) {  
	        if (s == null)  
	            return null;  
	        BASE64Encoder b = new sun.misc.BASE64Encoder();  
	        return b.encode(s);  
	    }  
	  
	    public static byte[] base64Decode(String s) throws IOException {  
	        if (s == null)  
	            return null;  
	        BASE64Decoder decoder = new BASE64Decoder();  
	        byte[] b = decoder.decodeBuffer(s);  
	        return b;  
	    }  
	  
	    public static void main(String[] args) throws Exception {  
	    	//定义密钥
	        String key = "BC0F84173486496C925B8814F19790E80AB1418257D94114"; 
	        //加密数据
	        String input = "十年生死两茫茫，不思量，自难相忘"; 
	        //调用加密
	        des_one crypt = new des_one(key);  
	        //加密输出
	        System.out.println("Encode:" + crypt.encrypt(input));
	        //解密输出
	        System.out.println("Decode:" +crypt.decrypt(crypt.encrypt(input)));  
	    }

}
