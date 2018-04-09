local function not_found(self, db, helpers)
  return helpers.responses.send_HTTP_NOT_FOUND()
end

return {
  -- GET / PATCH / DELETE /server_names/server_name are the only methods allowed

  ["/server_names"] = {
    before = not_found,
  },

  ["/server_names/:server_names/certificate"] = {
    before = not_found,
  },

}
