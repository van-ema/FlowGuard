(function () {
  const DEFAULT_TABLE = "demo_requests";
  const config = window.FlowguardSupabase || {};

  const form = document.querySelector("[data-demo-request-form]");
  const status = document.querySelector("[data-demo-request-status]");

  if (!form || !status) {
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const formData = new FormData(form);
    const email = String(formData.get("email") || "").trim();

    if (!email || !isValidEmail(email)) {
      setStatus("Enter a valid email address.", "error");
      return;
    }

    const publishableKey = config.publishableKey;

    if (!config.url || !publishableKey) {
      setStatus("Demo requests are not configured yet.", "error");
      return;
    }

    const button = form.querySelector("button");
    setLoading(button, true);
    setStatus("Submitting demo request...", "pending");

    try {
      await submitDemoRequest({
        url: String(config.url),
        publishableKey: String(publishableKey),
        table: String(config.table || DEFAULT_TABLE),
        email,
      });
      form.reset();
      setStatus("Request received. We will follow up by email.", "success");
    } catch (error) {
      console.error(error);
      setStatus("Could not submit the request. Try again later.", "error");
    } finally {
      setLoading(button, false);
    }
  });

  async function submitDemoRequest({ url, publishableKey, table, email }) {
    const endpoint = `${url.replace(/\/$/, "")}/rest/v1/${encodeURIComponent(table)}`;
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        apikey: publishableKey,
        Authorization: `Bearer ${publishableKey}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({ email }),
    });

    if (!response.ok) {
      throw new Error(`Supabase insert failed with HTTP ${response.status}`);
    }
  }

  function isValidEmail(email) {
    return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
  }

  function setStatus(message, kind) {
    status.textContent = message;
    status.dataset.status = kind;
  }

  function setLoading(button, isLoading) {
    if (!button) {
      return;
    }
    button.disabled = isLoading;
    button.textContent = isLoading ? "Submitting..." : "Book a demo";
  }
})();
