// SPDX-License-Identifier: MIT

// Each view owns one slot per replaceable request. A completed request can
// release only its own slot, even if its transport ignored cancellation.
class RequestSlot {
  current = null;

  begin(identity) {
    this.cancel();
    const request = { ...identity, controller: new AbortController() };
    this.current = request;
    return request;
  }

  cancel() {
    const request = this.current;
    this.current = null;
    request?.controller.abort();
  }

  owns(request) {
    return this.current === request;
  }

  finish(request) {
    if (this.owns(request)) this.current = null;
  }
}
