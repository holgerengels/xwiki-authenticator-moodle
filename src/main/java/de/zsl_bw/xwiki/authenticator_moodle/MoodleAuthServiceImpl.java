/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package de.zsl_bw.xwiki.authenticator_moodle;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import org.apache.commons.lang3.StringUtils;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;

import java.security.Principal;


/**
 * Implementation of the PAM authorization module.
 *
 * @version $Id$
 */
public class MoodleAuthServiceImpl extends XWikiAuthServiceImpl {
    private static final Logger LOGGER = LoggerFactory.getLogger(MoodleAuthenticator.class);

    private final MoodleAuthenticator authenticator = new MoodleAuthenticator(); // Utils.getComponent(MoodleAuthenticator.class);

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        String user = context.getRequest().getRemoteUser();
        if ((user == null) || user.equals("")) {
            return super.checkAuth(context);
        } else {
            LOGGER.debug("Launching create user for [{}]", user);
            createUser(user, context);
            LOGGER.debug("Create user done for [{}]", user);
            user = "XWiki." + user;
        }
        context.setUser(user);

        return new XWikiUser(user);
    }

    private static final EntityReference USERCLASS_REFERENCE = new EntityReference("XWikiUsers", EntityType.DOCUMENT,
            new EntityReference("XWiki", EntityType.SPACE));

    protected boolean checkPassword(String username, String password, XWikiContext context) throws XWikiException {
        if (authenticator.authenticate(username, password, context))
            return true;

        LOGGER.info("wiki: " + context.getWiki());
        LOGGER.info("wiki: " + context.getWikiId());
        final XWikiDocument doc = context.getWiki().getDocument(username, context);
        LOGGER.info("doc: " + doc);
        final BaseObject userObject = doc.getXObject(USERCLASS_REFERENCE);
        LOGGER.info("userObject: " + userObject);

        return super.checkPassword(username, password, context);
    }

    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException {
        if (username == null)
            return null;

        username = username.toLowerCase();

        if (StringUtils.isBlank(username)) {
            context.put("message", "nousername");
            return null;
        } else if (password != null && !password.isEmpty()) {
            String cannonicalUsername = username.replaceAll(" ", "");
            if (this.isSuperAdmin(cannonicalUsername)) {
                return this.authenticateSuperAdmin(password, context);
            } else {
                LOGGER.info("context: " + context.getWikiId());
                String susername = cannonicalUsername;
                int i = cannonicalUsername.indexOf(".");
                int j = cannonicalUsername.indexOf(":");

                if (i != -1) {
                    susername = cannonicalUsername.substring(i + 1);
                } else if (j > 0) {
                    susername = cannonicalUsername.substring(j + 1);
                }

                LOGGER.debug("username: " + username);
                LOGGER.debug("susername: " + susername);

                if (this.checkPassword(username, password, context)) {
                    LOGGER.debug("call findUser: " + susername, context.getWikiId());
                    String user = this.findUser(susername, context);
                    LOGGER.debug("user: " + user);
                    if (user == null) {
                        LOGGER.info("login from new user: " + username);
                        //getParam("auth_createuser", context);
                        user = createUser(username, context);
                        user = "XWiki." + user;
                        context.setUser(user);
                    }
                    else {
                        LOGGER.info("login from known user: " + username);
                    }
                    return new SimplePrincipal(context.getWikiId() + ":" + user);
                }
                else {
                    LOGGER.info("login failed for incorrect password: " + username);
                    context.put("message", "invalidcredentials");
                    return null;
                }
            }
        }
        else {
            context.put("message", "nopassword");
            return null;
        }
    }
}

