# 11/15/2017 - v5.0.0

* Drop Rails 4.2 support
* Add Appraisals
* Fix tests to use keyword arguments
* Fix bugs revealed by IntegrationTest converting `nil` to blank strings
* Addressed deprecations
* Upgraded dummy app

# 11/14/2017 - v4.2.0

* Add Ruby 2.4.0 and 2.4.1 support
* Drop Rails 4.1 support
* Update tests to address deprecations
* Replaced FactoryGirl with FactoryBot
* Fixed test that likely never worked, but did not fail because of deprecated gems
* Loosen gem versions
* Rubocop cleanup

# 9/26/2015

* Added ability to pass a `context` object when verifying user login, allowing to pass extra data such as HTTP request (e.g. subdomain) if needed [5a99dac8f83492d643c20719f2d911d27c933a68](https://github.com/identification-io/CASino/commit/5a99dac8f83492d643c20719f2d911d27c933a68)
