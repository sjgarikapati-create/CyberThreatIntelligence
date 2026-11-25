package utilities;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dao.CISADAO;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class CISADataFetcher {

    private static final String API_URL =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    public JsonArray fetchVulnerabilities()
            throws IOException, InterruptedException {

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = client.send(
                request,
                HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() != 200) {
            throw new IOException(
                "CISA request failed. HTTP Status: "
                + response.statusCode()
            );
        }

        JsonObject jsonObject =
                JsonParser.parseString(response.body()).getAsJsonObject();

        return jsonObject.getAsJsonArray("vulnerabilities");
    }

    public int fetchAndSaveData()
            throws IOException, InterruptedException {

        JsonArray vulnerabilities = fetchVulnerabilities();

        CISADAO dao = new CISADAO();

        dao.createTable();

        int savedCount = dao.saveVulnerabilities(vulnerabilities);

        System.out.println("LIVE CISA DATA FETCHED!");
        System.out.println("Vulnerabilities received: "
                + vulnerabilities.size());
        System.out.println("Records processed: " + savedCount);

        return savedCount;
    }

    public static void main(String[] args) {

        CISADataFetcher fetcher = new CISADataFetcher();

        try {

            fetcher.fetchAndSaveData();

        } catch (IOException | InterruptedException e) {

            System.out.println("CISA DATA FETCH FAILED!");
        }
    }
}