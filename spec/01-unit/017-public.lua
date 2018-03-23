local meta = require "kong.meta"


describe("Public API", function()
  it("returns the most recent version", function()
    local kong = require "kong.public"
    assert.equal("2.0.0", kong._sdk_version)
    assert.equal(20000,   kong._sdk_version_num)


    local version_num = tonumber(string.format("%02u%02u%02u",
                                               meta._VERSION_TABLE.major,
                                               meta._VERSION_TABLE.minor,
                                               meta._VERSION_TABLE.patch))

    assert.equal(meta._VERSION, kong._version)
    assert.equal(version_num,   kong._version_num)
  end)

  it("returns the most recent 2.x.x version", function()
    local kong = require "kong.public".v("1")
    assert.equal("1.0.1", kong._sdk_version)

    local kong = require "kong.public".v(1)
    assert.equal(10001,   kong._sdk_version_num)

    local kong = require "kong.public".v("1.0")
    assert.equal("1.0.1", kong._sdk_version)

    local kong = require "kong.public".v(1, 0)
    assert.equal(10001,   kong._sdk_version_num)
  end)

  it("returns requested version", function()
    local kong = require "kong.public".v("1.0.0")
    assert.equal("1.0.0", kong._sdk_version)
    assert.equal(10000,   kong._sdk_version_num)
  end)


  it("returns the most recent version for specific api", function()
    local kong = require "kong.public"
    assert.equal("1.0.1", kong.cache._version)
    assert.equal(10001,   kong.cache._version_num)
    assert.equal("1.0.0", kong.ctx._version)
    assert.equal(10000,   kong.ctx._version_num)
    assert.is_nil(kong.configuration)
  end)


  it("returns requested version for specific api", function()
    local kong = require "kong.public"
    assert.equal("1.0.0", kong.cache.v("1.0.0")._version)
    assert.equal(10000,   kong.cache.v(1, 0, 0)._version_num)
  end)
end)

