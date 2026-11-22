
from selenium import webdriver

driver = webdriver.Chrome()

try:
    driver.get("https://www.selenium.dev")
    print("Browser opened successfully!")
    print("Page title:", driver.title)
finally:
    driver.quit()
