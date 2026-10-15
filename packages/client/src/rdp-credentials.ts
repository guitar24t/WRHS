/**
 * The user name to give IronRDP for Network Level Authentication.
 *
 * Its sign-in library (sspi) splits "you@gmail.com" into user "you" and
 * domain "gmail.com". Windows then signs in a local account named "you", or
 * no one, and a Microsoft account never works. Windows' own Remote Desktop
 * client sends the whole address as the user, with an empty domain. sspi
 * does the same when the name ends in "@": it splits at the last "@", which
 * leaves the address as the user and an empty domain.
 */
export function nlaUsername(username: string, domain?: string): string {
  if (domain || username.includes('\\') || !username.includes('@') || username.endsWith('@')) return username;
  return `${username}@`;
}
