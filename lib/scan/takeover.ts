/**
 * Dangling-CNAME (subdomain takeover) detection.
 *
 * The bug: you point app.yourdomain.com at a hosting service with a CNAME, then
 * delete the app — but leave the DNS record. The name still resolves to the
 * provider, the provider no longer has anyone claiming it, and whoever claims it
 * next serves whatever they like on YOUR domain: real HTTPS, real brand, perfect
 * phishing. Vibe-coded projects churn through hosts constantly, so stale CNAMEs
 * are common.
 *
 * Precision matters more than coverage here. A CNAME to a hosting provider is
 * completely normal — that is how hosting works. It is only a finding when the
 * name points at a known provider AND that provider answers with its
 * "nobody has claimed this" page. Both, or nothing.
 */

export interface TakeoverService {
  name: string;
  /** CNAME targets that belong to this service. */
  cname: RegExp;
  /** What the provider serves when the name is unclaimed. */
  unclaimed: RegExp;
}

export const SERVICES: TakeoverService[] = [
  { name: 'GitHub Pages', cname: /\.github\.io$/i, unclaimed: /there isn'?t a github pages site here/i },
  { name: 'Heroku', cname: /\.herokuapp\.com$|\.herokudns\.com$/i, unclaimed: /no such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { name: 'Amazon S3', cname: /\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$/i, unclaimed: /<code>nosuchbucket<\/code>|the specified bucket does not exist/i },
  { name: 'Netlify', cname: /\.netlify\.(app|com)$/i, unclaimed: /not found\s*-\s*request id|page not found[\s\S]{0,200}netlify/i },
  { name: 'Vercel', cname: /\.vercel-dns\.com$|cname\.vercel-dns\.com$/i, unclaimed: /deployment_not_found|the deployment could not be found/i },
  { name: 'Shopify', cname: /\.myshopify\.com$/i, unclaimed: /sorry, this shop is currently unavailable/i },
  { name: 'Fastly', cname: /\.fastly(?:lb)?\.net$/i, unclaimed: /fastly error:\s*unknown domain/i },
  { name: 'Surge.sh', cname: /\.surge\.sh$/i, unclaimed: /project not found/i },
  { name: 'Azure', cname: /\.azurewebsites\.net$|\.cloudapp\.azure\.com$/i, unclaimed: /web site not found|404 web site not found/i },
  { name: 'Zendesk', cname: /\.zendesk\.com$/i, unclaimed: /help center closed|this help center no longer exists/i },
  { name: 'Webflow', cname: /\.proxy-ssl\.webflow\.com$|\.webflow\.io$/i, unclaimed: /the page you are looking for doesn'?t exist[\s\S]{0,200}webflow/i },
  { name: 'Ghost', cname: /\.ghost\.io$/i, unclaimed: /domain error[\s\S]{0,120}ghost/i },
  { name: 'Bitbucket', cname: /\.bitbucket\.io$/i, unclaimed: /repository not found/i },
  { name: 'Pantheon', cname: /\.pantheonsite\.io$/i, unclaimed: /the gods are wise|404 error unknown site/i },
];

export type TakeoverVerdict = 'vulnerable' | 'dangling' | 'safe' | 'not-applicable';

export interface TakeoverFinding {
  verdict: TakeoverVerdict;
  service?: string;
  cname?: string;
  detail: string;
}

export interface TakeoverFacts {
  /** CNAME target for the scanned host, if any. */
  cname: string | null;
  /** whether the CNAME target itself resolves at all (NXDOMAIN => dangling). */
  cnameResolves: boolean;
  /** body served at the host. */
  body: string;
  status: number;
}

export function classifyTakeover(facts: TakeoverFacts): TakeoverFinding {
  const { cname, cnameResolves, body } = facts;
  if (!cname) {
    return { verdict: 'not-applicable', detail: 'this host has no CNAME, so there is nothing to take over' };
  }

  const service = SERVICES.find((s) => s.cname.test(cname));

  // A CNAME whose TARGET does not resolve is dangling regardless of provider.
  if (!cnameResolves) {
    return {
      verdict: 'dangling',
      cname,
      service: service?.name,
      detail: `points at ${cname}, which does not resolve — if anyone can register that name they control this hostname`,
    };
  }

  if (!service) {
    return { verdict: 'safe', cname, detail: `points at ${cname} (not a service with a known takeover pattern)` };
  }

  // The decisive test: the provider itself says nobody has claimed this name.
  if (service.unclaimed.test(body)) {
    return {
      verdict: 'vulnerable',
      service: service.name,
      cname,
      detail: `${service.name} is serving its "unclaimed" page for this hostname — anyone who claims it there can serve their own content on your domain`,
    };
  }

  return { verdict: 'safe', service: service.name, cname, detail: `points at ${service.name} and is claimed` };
}
