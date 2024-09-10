package de.zsl_bw.xwiki.authenticator_moodle;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

//@Component(roles = MoodleAuthenticator.class)
//@Singleton
public class MoodleAuthenticator {
    private static final Logger LOGGER = LoggerFactory.getLogger(MoodleAuthenticator.class);

    public boolean authenticate(String username, String password, XWikiContext context) throws XWikiException {
        try {
            URL url = new URL("https://fachnetz-bs.zsl-bw.de/login/token.php");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            Map<String, String> parameters = new HashMap<>();
            parameters.put("username", username);
            parameters.put("password", password);
            parameters.put("service", "moodle_mobile_app");
            con.setDoOutput(true);
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);
            DataOutputStream out = new DataOutputStream(con.getOutputStream());
            out.writeBytes(getParamsString(parameters));
            out.flush();
            out.close();
            int status = con.getResponseCode();
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            con.disconnect();
            LOGGER.debug("content " + content);
            JSONObject jsonObject = new JSONObject(content.toString());
            return !jsonObject.has("errorcode") && jsonObject.getString("token") != null;
        }
        catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return false;
        }
    }

    public static String getParamsString(Map<String, String> params) {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
            result.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            result.append("&");
        }

        String resultString = result.toString();
        return resultString.length() > 0
                ? resultString.substring(0, resultString.length() - 1)
                : resultString;
    }

    public static void main(String[] args) {
        try {
            boolean authenticated = new MoodleAuthenticator().authenticate("holgerengels", "Efel@nt7", null);
            System.out.println("authenticated = " + authenticated);
        } catch (XWikiException e) {
            e.printStackTrace();
        }
    }
}
