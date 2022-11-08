import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.print.attribute.IntegerSyntax;

/**
 *
 * @author Hassane AISSAOUI-MEHREZ
 */
public class PIN_Code_Attack {
    static int nbreCombinaison = 10;
    static long TimeinMilliSec = 0;
    static int err = 32;
    static int lenPinCode = 4;
    static int lenPattern = 9;
    static byte[] PwdToHash = new byte[lenPinCode];
    static byte[] PatternToHash = new byte[lenPattern];
    static String alphanum = new String("0123456789azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN");

    public static void Get_Times() {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat DateFormat = new SimpleDateFormat("HH:mm:ss"); // ("HH:mm:ss:mm");
        System.out.println(DateFormat.format(calendar.getTimeInMillis()));
        if (TimeinMilliSec == 0) {
            TimeinMilliSec = calendar.getTimeInMillis();
            return;
        }
        TimeinMilliSec = calendar.getTimeInMillis() - TimeinMilliSec;
        System.out.println("Time is : " + TimeinMilliSec + " milliseconds");
    }

    public static void msgprintf(byte[] msgprint) {
        int i;
        for (i = 0; i < msgprint.length; i++) {
            System.out.printf("%02X", msgprint[i]);
        }
        System.out.println();
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes();
    public static String toHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    // construction recursive des mots de passe possibles et hachage
    public static void Brute_Force_Attack(String Salted_Pwd, String Salt, int index) {
        String New_Hash = null;
        if (index >= lenPinCode) {
            String New_PwdToHash = new String(PwdToHash);
            New_Hash = passwordToHash(New_PwdToHash, Salt);
            //System.out.println(New_PwdToHash + " " + New_Hash);
            if (Salted_Pwd.compareTo(New_Hash) == 0) {
                System.out.print("The PIN code is: ");
                System.out.println(New_PwdToHash);
                System.out.print("SHA-1 + MD5 Hashes of PIN Code: ");
                System.out.println(New_Hash);
                err = 0;
            }
            return;
        }
        for (int i = 0; i < nbreCombinaison; i++) {
            if (err == 0) {
                break;
            }
            PwdToHash[index] = (byte) alphanum.charAt(i); // (byte) (i + '0');
            Brute_Force_Attack(Salted_Pwd, Salt, index + 1);
        }
    }

    public static void Brute_Force_Attack_Pattern(String Salted_Pwd, int index) {
        String New_Hash = null;
        byte[] hex_list = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        if (index >= lenPattern) {
            New_Hash = patternToHash(PatternToHash);
            if (Salted_Pwd.compareTo(New_Hash) == 0) {
                System.out.print("The Pattern code is: ");
                msgprintf(PatternToHash);
                System.out.print("SHA-1 Hash of Pattern: ");
                System.out.println(New_Hash);
                err = 0;
            }
            return;
        }
        for (int i = 0; i < hex_list.length; i++) {
            if (err == 0) {break;}
            PatternToHash[index] = hex_list[i];
            Brute_Force_Attack_Pattern(Salted_Pwd, index + 1);
        }
    }

    public static String passwordToHash (String password, String salt) {
        if (password == null) {
            return null;
        }
        String algo = null;
        String hashed = null;
        try {
            byte[] saltedPassword = (password + salt).getBytes();
            byte[] sha1 = MessageDigest.getInstance(algo="SHA-1").digest(saltedPassword);
            byte[] md5 = MessageDigest.getInstance(algo="MD5").digest(saltedPassword);
            hashed = toHex(sha1) + toHex(md5);
        }
        catch (Exception e) {
            System.out.println("Failed to encode string because of missing algorithm: "+ algo);
        
        }
        return hashed;
    }

    public static String patternToHash (byte[] password) {
        if (password == null) {
            return null;
        }
        String algo = null;
        String hashed = null;
        try {
            byte[] sha1 = MessageDigest.getInstance(algo="SHA-1").digest(password);
            hashed = (toHex(sha1));
        }
        catch (Exception e) {
            System.out.println("Failed to encode string because of missing algorithm: "+ algo);
        }
        return hashed;
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

        String Salted_Pwd = "B18A3F7CBEB3C0A9568EEDB03EA61D614D2CDB89D39F54850872E950E7DCF88021E33A55";
        String Salt = "1ee096a29e471413";

        // Get_Times();
        // Brute_Force_Attack(Salted_Pwd, Salt, 0);
        // Get_Times();
        
        TimeinMilliSec = 0;
        String Salted_Pattern = "CC6B4D33A317D9ED30C411A03C0389F5BB42F8C1";
        Get_Times();
        Brute_Force_Attack_Pattern(Salted_Pattern, 0);
        Get_Times();
    }
}