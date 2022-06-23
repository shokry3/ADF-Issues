package gov.riyadh.amana.template.view.util;

import gov.riyadh.amana.modules.ModuleFactory;

import java.io.IOException;

import java.math.BigDecimal;

import java.time.temporal.ChronoField;

import java.util.Calendar;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import javax.security.auth.Subject;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import jcifs.ntlmssp.Type3Message;

import weblogic.security.URLCallbackHandler;
import weblogic.security.services.Authentication;

//Added by shokry 20-06-2021
//Used for auto login by default user "9000046" and navigate to home page for STRESS TEST
//Just activate the servlet @WebServlet bellow tag "url" to work  & deploy this lib.
//No need for any extra configurations.
@WebServlet(value = { "/loginApi*", "/loginApi" })
public class loginServlet extends HttpServlet {
    public loginServlet() {
        super();
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws ServletException, IOException {

        ModuleFactory factory = new ModuleFactory();
        HttpSession session = httpServletRequest.getSession();
        String userCode = null;
        String userName = null;
        try {


            String auth = httpServletRequest.getHeader("Authorization");
            //System.out.println("auth : " + auth);
            if (auth == null) {
                httpServletResponse.setHeader("WWW-Authenticate", "NTLM");
                httpServletResponse.setStatus(httpServletResponse.SC_UNAUTHORIZED);
                httpServletResponse.setContentLength(0);
                httpServletResponse.flushBuffer();
                return;
            }
            if (auth.startsWith("NTLM ")) {
                byte[] msg = new sun.misc.BASE64Decoder().decodeBuffer(auth.substring(5));
                //System.out.println("msg : " + msg);
                int off = 0, length, offset;
                if (msg[8] == 1) {
                    off = 18;

                    byte z = 0;
                    byte[] msg1 = {
                        (byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P', z, (byte) 2,
                        z, z, z, z, z, z, z, (byte) 40, z, z, z, (byte) 1, (byte) 130, z, z, z, (byte) 2, (byte) 2,
                        (byte) 2, z, z, z, z, //
                        z, z, z, z, z, z, z, z
                    };
                    // send ntlm type2 msg

                    httpServletResponse.setStatus(httpServletResponse.SC_UNAUTHORIZED);
                    httpServletResponse.setHeader("WWW-Authenticate",
                                                  "NTLM " + new sun.misc.BASE64Encoder().encodeBuffer(msg1).trim());
                    httpServletResponse.setContentLength(0);
                    httpServletResponse.flushBuffer();
                    return;
                } else if (msg[8] == 3) {
                    //Did Authentication Succeed? All this is always printed.

                    Type3Message type3 = new Type3Message(msg);

                    System.out.println("osUser: " + type3.getUser());

                    userName = type3.getUser(); //httpServletRequest.getRemoteHost();
                    //session.setAttribute("OneUserLggedSession", userName);
                    userCode = getLdabUserCode(userName);
                    System.out.println("get LDAB UserCode : " + userCode);
                    if (userCode == null || userCode.isEmpty()) {
                        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/faces/login");
                    } else {
                        session.setAttribute("OneUserLggedSession", userName);
                        String hostName = null;
                        if (hostName == null) {
                            hostName = httpServletRequest.getRemoteAddr();
                        }
                        Map<String, Object> userResources = factory.getSecurityProvider().getUserResources(userCode);
                        String  pw = (String) userResources.get("PASSWORD");
                        URLCallbackHandler cbh = new URLCallbackHandler(userCode, pw.getBytes());
                        Subject subject = Authentication.login(cbh);
                        weblogic.servlet.security.ServletAuthentication.runAs(subject, httpServletRequest);
                        weblogic.servlet.security.ServletAuthentication.generateNewSessionID(httpServletRequest);
                        UserBean sessionData =
                            createUserSession(userCode, userResources, hostName, httpServletRequest.getRemoteAddr(),
                                              httpServletRequest.getRequestURI());
                        session.setAttribute("UserBean", sessionData);
                        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/faces/home");
                        System.out.println("user login success .........");
                    }

                }
            }
        } catch (Exception fle) {
            fle.printStackTrace();
        }
    }

    protected static UserBean createUserSession(String uName, Map<String, Object> userResources, String hostName,
                                                String hostIp, String requestURI) {
        UserBean sessionData = new UserBean();
        sessionData.setUserCode(uName);
        sessionData.setLang(Constants.AR_LANG);
        Calendar cal = Calendar.getInstance();
        sessionData.setHijrahDate(gov.riyadh.amana.template.model.util.HijriUtil.now());
        sessionData.setGregorianDate(new java.sql.Timestamp(cal.getTime().getTime()));
        sessionData.setHijriDate(gov.riyadh.amana.template.model.util.HijriUtil.toHijri(sessionData.getGregorianDate()));
        sessionData.setSpecialHijriDate(new java.sql.Timestamp(gov.riyadh.amana.template.model.util.HijriUtil.getSpecialDate(sessionData.getHijriDate())));
        sessionData.setUserIp(hostIp);
        sessionData.setUserMachineName(hostName);
        sessionData.getCustomFlags().put("Year", cal.get(Calendar.YEAR));
        sessionData.getCustomFlags().put("HijriYear", sessionData.getHijrahDate().get(ChronoField.YEAR));
        sessionData.getCustomFlags().putAll(userResources);
        if (sessionData.getCustomFlags() != null) {
            sessionData.setUserType(sessionData.getCustomFlags().get("USER_TYPE_CODE") == null ? 0 :
                                    ((BigDecimal) sessionData.getCustomFlags().get("USER_TYPE_CODE")).intValue());
            sessionData.setDeptCode("" + sessionData.getCustomFlags().get("DIR_CODE"));
            sessionData.setDeptName((String) sessionData.getCustomFlags().get("DIR_DESC"));
            sessionData.setFullName((String) sessionData.getCustomFlags().get("USER_NAME"));
            sessionData.setName((String) sessionData.getCustomFlags().get("USER_NAME"));
            sessionData.setJobDesc((String) sessionData.getCustomFlags().get("JOB_NAME"));
            sessionData.setAdUser((String) sessionData.getCustomFlags().get("AD_NAME"));
            sessionData.setAccountDirCode((String) sessionData.getCustomFlags().get("ACCOUNT_DIR"));
            sessionData.setEmpNameEn((String) sessionData.getCustomFlags().get("EMP_NAME_EN"));
            sessionData.setEmpJobName((String) sessionData.getCustomFlags().get("EMP_JOB"));
            sessionData.setEmpHasFinger((BigDecimal) sessionData.getCustomFlags().get("EMP_HAS_FINGER"));
            sessionData.setEmpFirstFinger((String) sessionData.getCustomFlags().get("EMP_FIRST_FINGER"));
            sessionData.setEmpLastFinger((String) sessionData.getCustomFlags().get("EMP_LAST_FINGER"));
            sessionData.setUserPicturePath((String) sessionData.getCustomFlags().get("USER_PICTURE_PATH"));
            sessionData.setGender(sessionData.getCustomFlags().get("GENDER_FLAG") == null ? 0 :
                                  ((BigDecimal) sessionData.getCustomFlags().get("GENDER_FLAG")).intValue());
            sessionData.setMobileNo((String) sessionData.getCustomFlags().get("USER_MOBILE_NO"));
            sessionData.setEmail((String) sessionData.getCustomFlags().get("USER_EMAIL"));
            // ADDED BY MR
            sessionData.setUserPassword((String) sessionData.getCustomFlags().get("PASSWORD"));
        }
        if (Constants.APP_CONTEXT_NAME.equals(Constants.MAIN_SYSTEM)) {
            sessionData.getCustomFlags().put(Constants.MAIN_SYSTEM_URL, requestURI);
        }

        return sessionData;
    }

    //Added by SHOKRY - CHECK Logged User From Active Directory - 31-10-2021
    protected static String getLdabUserCode(String userName) {
        String userCode = null;
        LdapContext ctx = null;
        try {
            //First - connect
            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.SECURITY_AUTHENTICATION, "Simple");
            //mShehata@alriyadh.gov.sa
            //NOTE: replace user@domain.com with a User that is present in your Active Directory/LDAP
            env.put(Context.SECURITY_PRINCIPAL, "ADF@itamana.net");
            //NOTE: replace userpass with passwd of this user.
            env.put(Context.SECURITY_CREDENTIALS, ")@$#893jofdLKJFDL");
            //NOTE: replace ADorLDAPHost with your Active Directory/LDAP Hostname or IP.
            env.put(Context.PROVIDER_URL, "ldap://amndc.itamana.net:389");
            ctx = new InitialLdapContext(env, null);
            //Second - get user detail
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            //NOTE: The attributes mentioned in array below are the ones that will be retrieved, you can add more.
            String[] attrIDs = {
                "distinguishedName", "sn", "givenname", "mail", "telephonenumber", "canonicalName",
                "userAccountControl", "accountExpires", "physicalDeliveryOfficeName"
            };
            constraints.setReturningAttributes(attrIDs);

            //NOTE: replace DC=domain,DC=com below with your domain info. It is essentially the Base Node for Search.
            NamingEnumeration answer = ctx.search("DC=ITamana,DC=net", "SamAccountName=" + userName, constraints);

            if (answer.hasMore()) {
                Attributes attrs = ((SearchResult) answer.next()).getAttributes();
                if (attrs != null && attrs.get("physicalDeliveryOfficeName") != null) {
                    userCode = (String) attrs.get("physicalDeliveryOfficeName").get();
                }
            } else {
                userCode = null;
                throw new Exception("Invalid User");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            userCode = null;
        }
        return userCode;
    }

    public static void main(String args[]) //static method
    {
        System.out.println("Static method");
    }
}
