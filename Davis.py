import re
import time
from playwright.sync_api import Playwright, sync_playwright, expect

def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    page.wait_for_load_state()
    page.goto("http://0.0.0.0:8001/")
    page.locator(".navbar-brand").click()
    page.get_by_role("link", name="Home").click()
    page.get_by_role("link", name="Find owners").click()
    page.get_by_role("link", name="Veterinarians").click()
    page.get_by_role("link", name="Error").click()
    page.get_by_role("link", name="Find owners").click()
    page.get_by_role("textbox").click()
    page.get_by_role("textbox").fill("Davis")
    page.get_by_role("button", name="Find Owner").click()

    # ---------------------
    context.close()
    browser.close()

with sync_playwright() as playwright:
    run(playwright)

