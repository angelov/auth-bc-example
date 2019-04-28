package me.angelovdejan.authbcexample.authentication.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import me.angelovdejan.authbcexample.authentication.Credentials;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest
public class AuthenticationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void test_trying_to_authenticate_without_credentials() throws Exception {
        this.mockMvc.perform(post("/authentication/login"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void test_trying_to_authenticate_with_invalid_credentials() throws Exception {
        Credentials invalidCredentials = new Credentials("something@example.com", "invalid");

        this.mockMvc.perform(post("/authentication/login").contentType(APPLICATION_JSON_UTF8).content(convertObjectToJsonBytes(invalidCredentials)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void test_authenticating_with_correct_credentials() throws Exception {
        Credentials credentials = new Credentials("user@example.com", "password");

        this.mockMvc.perform(post("/authentication/login").contentType(APPLICATION_JSON_UTF8).content(convertObjectToJsonBytes(credentials)))
                .andExpect(status().isOk());
    }

    public static byte[] convertObjectToJsonBytes(Object object) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return mapper.writeValueAsBytes(object);
    }
}
