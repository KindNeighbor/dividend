package zerobase.dividend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import zerobase.dividend.model.Company;
import zerobase.dividend.scraper.Scraper;
import zerobase.dividend.scraper.YahooFinanceScraper;

@SpringBootApplication
public class DividendApplication {

	public static void main(String[] args) {
		SpringApplication.run(DividendApplication.class, args);
	}
}
