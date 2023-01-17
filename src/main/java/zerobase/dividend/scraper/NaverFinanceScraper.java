package zerobase.dividend.scraper;

import org.springframework.stereotype.Component;
import zerobase.dividend.model.Company;
import zerobase.dividend.model.ScrapedResult;

@Component
public class NaverFinanceScraper implements Scraper {

    @Override
    public Company scrapCompanyByTicker(String ticker) {
        return null;
    }

    @Override
    public ScrapedResult scrap(Company company) {
        return null;
    }
}
