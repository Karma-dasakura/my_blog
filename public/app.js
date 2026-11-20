const $ = (selector) => document.querySelector(selector);
const page = document.body.dataset.page;
let currentUser = null;
let categories = [];

// CSRF
const csrf = () => {
    const match = document.cookie.match(new RegExp("(^| )csrf_token=([^;]+)"));
    return match ? match[2] : "";
};

const escapeHtml = (value = "") =>
    String(value).replace(
        /[&<>'"]/g,
        (char) =>
            ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[
            char
            ]
    );

function showNotice(message, success = false) {
    const target = $("#notice");
    if (!target) return;
    target.textContent = message;
    target.classList.toggle("success", success);
}

async function ensureCsrfToken() {
    if (csrf()) return;
    const response = await fetch("/api/csrf", { credentials: "include" });
    if (!response.ok || !csrf()) throw new Error("Security setup failed. Refresh the page and try again.");
}

async function api(path, options = {}) {
    const headers = { "X-CSRF-Token": csrf(), ...(options.headers || {}) };
    if (options.body) headers["Content-Type"] = "application/json";

    let response;
    try {
        response = await fetch(`/api${path}`, {
            credentials: "include",
            ...options,
            headers,
        });
    } catch {
        throw new Error("Cannot reach MyBlog. Check that the server is running and your internet connection is available.");
    }

    let data;
    try {
        data = await response.json();
    } catch {
        if (response.status === 503) throw new Error("Bad database connection. Please check your internet, DNS settings, and Supabase host.");
        if (response.status >= 500) throw new Error("The service is temporarily unavailable. Please try again shortly.");
        throw new Error("The request could not be completed. Please refresh the page and try again.");
    }

    if (!response.ok) throw new Error(data.error || "Request failed.");
    return data;
}

function date(value) {
    return new Date(value).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
    });
}

function card(post, mine = false) {
    return `<article class="post-card"><span class="tag">${escapeHtml(post.category || "Uncategorized")}</span><h2><a href="/post.html?id=${post.id}">${escapeHtml(post.title)}</a></h2><p class="post-excerpt">${escapeHtml(post.content.slice(0, 145))}${post.content.length > 145 ? "…" : ""}</p><p class="post-meta">By ${escapeHtml(post.author)} · ${date(post.createdAt)} · ${post.commentCount || 0} comments</p>${mine ? `<div class="post-actions"><button class="mini-button" data-edit="${post.id}">Edit</button><button class="mini-button danger" data-delete="${post.id}">Delete</button></div>` : ""}</article>`;
}

async function updateNavigation() {
    try {
        currentUser = (await api("/auth/me")).user;
    } catch {
        currentUser = null;
    }

    document.querySelectorAll(".guest").forEach((element) => {
        element.hidden = Boolean(currentUser);
    });
    document.querySelectorAll(".member").forEach((element) => {
        element.hidden = !currentUser;
    });

    //Show Admin Link only for admins
    const adminNav = $("#adminNavLink");
    if (adminNav) {
        adminNav.hidden = !currentUser || currentUser.role !== 'admin';
    }

    const heroPrimary = $("#heroPrimary");
    if (heroPrimary) {
        if (currentUser) {
            heroPrimary.textContent = "Start writing";
            heroPrimary.href = "/dashboard.html#editor";
        } else {
            heroPrimary.textContent = "Create your account";
            heroPrimary.href = "/register.html";
        }
    }
    document.body.classList.remove("auth-loading");
}

async function loadCategories() {
    categories = (await api("/posts/categories")).categories;
    const filter = $("#categoryFilter");
    if (filter)
        filter.innerHTML =
            '<option value="">All categories</option>' +
            categories
                .map(
                    (item) =>
                        `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}</option>`,
                )
                .join("");
    const editor = $("#postCategory");
    if (editor)
        editor.innerHTML =
            '<option value="">Uncategorized</option>' +
            categories
                .map(
                    (item) =>
                        `<option value="${item.id}">${escapeHtml(item.name)}</option>`,
                )
                .join("");
}

async function loadFeed() {
    const destination = $("#postList");
    if (!destination) return;
    const category = $("#categoryFilter")?.value;
    try {
        const data = await api(
            `/posts${category ? `?category=${encodeURIComponent(category)}` : ""}`,
        );
        destination.innerHTML = data.posts.length
            ? data.posts.map((post) => card(post)).join("")
            : '<p class="empty">No stories have been published here yet.</p>';
    } catch (error) {
        destination.innerHTML = `<p class="empty">${escapeHtml(error.message)}</p>`;
    }
}

async function initHomeOrExplore() {
    await loadCategories();
    await loadFeed();
    $("#categoryFilter")?.addEventListener("change", loadFeed);
}

async function initAuth(kind) {
    if (currentUser) {
        location.href = "/dashboard.html";
        return;
    }
    const form = $(`#${kind}Form`);
    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = form.querySelector("button");
        button.disabled = true;
        try {
            const data = await api(`/auth/${kind}`, {
                method: "POST",
                body: JSON.stringify(Object.fromEntries(new FormData(form))),
            });
            showNotice(data.message, true);
            setTimeout(() => {
                location.href = "/dashboard.html";
            }, 300);
        } catch (error) {
            showNotice(error.message);
        } finally {
            button.disabled = false;
        }
    });
}

function clearEditor() {
    $("#postForm").reset();
    $("#editingId").value = "";
    $("#formTitle").textContent = "Write something new";
    $("#publishButton").textContent = "Publish story";
    $("#cancelEdit").hidden = true;
}

async function loadMine() {
    const destination = $("#myPostList");
    const data = await api("/posts/mine");
    destination.innerHTML = data.posts.length
        ? data.posts.map((post) => card(post, true)).join("")
        : '<p class="empty">Your first story is waiting. Use the editor above to publish it.</p>';
    return data.posts;
}

async function initDashboard() {
    if (!currentUser) {
        location.href = "/login.html";
        return;
    }
    $("#welcome").textContent = `${currentUser.name}'s writing`;
    await loadCategories();
    let posts = await loadMine();
    $("#postForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        const id = $("#editingId").value;
        try {
            await api(`/posts${id ? `/${id}` : ""}`, {
                method: id ? "PUT" : "POST",
                body: JSON.stringify(
                    Object.fromEntries(new FormData(event.currentTarget)),
                ),
            });
            clearEditor();
            showNotice(
                id ? "Your story has been updated." : "Your story is now published.",
                true,
            );
            posts = await loadMine();
        } catch (error) {
            showNotice(error.message);
        }
    });
    $("#cancelEdit").onclick = clearEditor;
    document.addEventListener("click", async (event) => {
        const id = event.target.dataset.edit;
        const remove = event.target.dataset.delete;
        if (id) {
            const post = posts.find((item) => String(item.id) === id);
            if (!post) return;
            $("#editingId").value = post.id;
            $("#postForm [name=title]").value = post.title;
            $("#postForm [name=content]").value = post.content;
            const category = categories.find((item) => item.name === post.category);
            $("#postCategory").value = category?.id || "";
            $("#formTitle").textContent = "Edit your story";
            $("#publishButton").textContent = "Save changes";
            $("#cancelEdit").hidden = false;
            location.hash = "editor";
        }
        if (remove && confirm("Delete this story permanently?")) {
            try {
                await api(`/posts/${remove}`, { method: "DELETE" });
                showNotice("Story deleted.", true);
                posts = await loadMine();
            } catch (error) {
                showNotice(error.message);
            }
        }
    });
}

async function initPost() {
    const id = new URLSearchParams(location.search).get("id");
    if (!/^\d+$/.test(id || "")) {
        $("#postView").innerHTML = "<p>This story could not be found.</p>";
        return;
    }
    try {
        const data = await api(`/posts/${id}`);
        const post = data.post;
        $("#postView").innerHTML =
            `<span class="tag">${escapeHtml(post.category || "Uncategorized")}</span><h1>${escapeHtml(post.title)}</h1><p class="post-meta">By ${escapeHtml(post.author)} · ${date(post.createdAt)} · ${post.commentCount} comments</p><p class="reading-content">${escapeHtml(post.content)}</p><section class="comments"><h2>Responses</h2><div id="commentList">${data.comments.length ? data.comments.map((comment) => `<div class="comment"><div class="comment-meta"><strong>${escapeHtml(comment.author)}</strong> · ${date(comment.created_at)}</div>${escapeHtml(comment.body)}</div>`).join("") : '<p class="post-excerpt">No responses yet. Start the conversation.</p>'}</div>${currentUser ? '<form id="commentForm" class="comment-form"><label>Leave a response<textarea name="body" minlength="2" maxlength="1000" required placeholder="Share a thoughtful response"></textarea></label><button class="button">Post response</button></form>' : '<p class="post-excerpt">Want to join the conversation? <a href="/login.html">Log in</a>.</p>'}</section>`;
        $("#commentForm")?.addEventListener("submit", async (event) => {
            event.preventDefault();
            try {
                await api(`/posts/${id}/comments`, {
                    method: "POST",
                    body: JSON.stringify(
                        Object.fromEntries(new FormData(event.currentTarget)),
                    ),
                });
                location.reload();
            } catch (error) {
                showNotice(error.message);
            }
        });
    } catch (error) {
        $("#postView").innerHTML = `<p>${escapeHtml(error.message)}</p>`;
    }
}

async function initAdmin() {
    if (!currentUser || currentUser.role !== 'admin') {
        location.href = "/dashboard.html"; // Kick non-admins out
        return;
    }

    try {
        // 1. Load Users
        const userData = await api("/posts/admin/users");
        const userTbody = $("#userList");
        if (!userData.users.length) {
            userTbody.innerHTML = '<tr><td colspan="5">No users found.</td></tr>';
        } else {
            userTbody.innerHTML = userData.users.map(user => `
        <tr>
          <td>#${user.id}</td>
          <td>${escapeHtml(user.display_name)}</td>
          <td><span class="tag" style="color: ${user.role === 'admin' ? 'var(--danger)' : 'var(--forest)'}">${escapeHtml(user.role)}</span></td>
          <td>${date(user.created_at)}</td>
          <td>
            ${user.role !== 'admin' ? `<button class="btn-danger" data-delete-user="${user.id}">Delete User</button>` : '<em>Protected</em>'}
          </td>
        </tr>
      `).join("");
        }

        // 2. Load Posts (Using the existing GET /api/posts endpoint)
        const postData = await api("/posts");
        const postTbody = $("#adminPostList");
        if (!postData.posts.length) {
            postTbody.innerHTML = '<tr><td colspan="5">No posts found.</td></tr>';
        } else {
            postTbody.innerHTML = postData.posts.map(post => `
        <tr>
          <td>#${post.id}</td>
          <td><a href="/post.html?id=${post.id}" target="_blank" style="color: var(--forest); font-weight: bold;">${escapeHtml(post.title)}</a></td>
          <td>${escapeHtml(post.author)}</td>
          <td>${date(post.createdAt)}</td>
          <td><button class="btn-danger" data-delete-post="${post.id}">Delete Post</button></td>
        </tr>
      `).join("");
        }

        // 3. Handle Delete Actions (Event Delegation)
        document.addEventListener("click", async (event) => {
            const deleteUserId = event.target.dataset.deleteUser;
            const deletePostId = event.target.dataset.deletePost;

            // Delete User
            if (deleteUserId) {
                if (confirm("WARNING: Are you sure you want to permanently delete this user? All their posts and comments will also be deleted.")) {
                    try {
                        await api(`/auth/admin/users/${deleteUserId}`, { method: "DELETE" });
                        showNotice("User deleted successfully.", true);
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        showNotice(error.message);
                    }
                }
            }

            // Delete Post
            if (deletePostId) {
                if (confirm("Are you sure you want to permanently delete this post?")) {
                    try {
                        await api(`/posts/${deletePostId}`, { method: "DELETE" });
                        showNotice("Post deleted successfully.", true);
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        showNotice(error.message);
                    }
                }
            }
        });

    } catch (error) {
        showNotice(error.message);
    }
}
async function logout() {
    try {
        await api("/auth/logout", { method: "POST" });
        location.href = "/";
    } catch (error) {
        alert(error.message);
    }
}

document
    .querySelectorAll("[data-logout]")
    .forEach((button) => button.addEventListener("click", logout));


(async () => {
    try {
        await ensureCsrfToken();
        await updateNavigation(); // This checks who is logged in

        // Initialize page-specific logic
        if (page === "home" || page === "explore") await initHomeOrExplore();
        if (page === "login" || page === "register") await initAuth(page);
        if (page === "dashboard") await initDashboard();
        if (page === "post") await initPost();
        if (page === "admin") await initAdmin();

    } catch (error) {
        console.error(error);
        showNotice(error.message);
        const postList = $("#postList");
        if (postList) postList.innerHTML = `<p class="empty">${escapeHtml(error.message)}</p>`;
    } finally {
        // ALWAYS hide the loader and allow scrolling once everything is done
        document.body.classList.remove("auth-loading");
        const loader = document.getElementById("pageLoader");
        if (loader) {
            loader.classList.add("hidden");
        }
    }
})();