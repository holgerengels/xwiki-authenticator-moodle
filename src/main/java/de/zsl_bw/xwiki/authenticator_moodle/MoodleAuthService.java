package de.zsl_bw.xwiki.authenticator_moodle;

import org.xwiki.component.annotation.Component;
import org.xwiki.security.authservice.AbstractXWikiAuthServiceWrapper;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import javax.inject.Named;
import javax.inject.Singleton;

@Component
@Singleton
@Named(MoodleAuthService.ID)
public class MoodleAuthService extends AbstractXWikiAuthServiceWrapper implements XWikiAuthServiceComponent {
    /**
     * The identifier of the authenticator.
     */
    public static final String ID = "moodleauth";

    public MoodleAuthService() {
        super(new MoodleAuthServiceImpl());
    }

    @Override
    public String getId() {
        return ID;
    }
}