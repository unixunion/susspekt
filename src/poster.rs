use reqwest::Error;

// Define the struct
pub struct HttpPoster {
    client: reqwest::Client,
}

impl HttpPoster {
    // Constructor for the struct
    pub fn new() -> Self {
        HttpPoster {
            client: reqwest::Client::new(),
        }
    }

    // Async method to post data
    pub async fn post_data(&self, url: &str, data: &str) -> Result<(), Error> {
        self.client.post(url)
            .body(String::from(data))
            .send()
            .await?;
        Ok(())
    }
}
