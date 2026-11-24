import React from 'react';

export type Tone = 'ok' | 'warn' | 'bad' | 'accent' | 'idle' | 'plain';

const MARK_PATH =
  'M130.50000,32.69817L91.68666,44.82734L91.50000,44.67666L91.50000,44.88567L52.85411,56.96251L52.50000,56.67666L52.50000,57.07317L28.50000,64.57317L28.50000,169.23933L66.84865,157.25538L73.39830,162.54245L21.50000,178.76067L21.50000,59.42683L156.50000,17.23933L156.50000,53.66461L149.50000,48.01401L149.50000,26.76067L130.51921,32.69217L130.50000,32.67666ZM213.50000,179.67666L207.70652,175.00000L209.00000,175.00000L209.00000,109.00000L205.00000,109.00000L205.00000,172.81522L181.50000,153.84534L181.50000,117.32727L137.50000,81.80919L137.50000,47.32334L213.50000,108.67273ZM98.50000,59.32334L174.50000,120.67273L174.50000,191.67666L168.70652,187.00000L170.00000,187.00000L170.00000,121.00000L166.00000,121.00000L166.00000,184.81522L142.50000,165.84534L142.50000,129.32727L98.50000,93.80919ZM59.50000,71.32334L135.50000,132.67273L135.50000,203.67666L129.70652,199.00000L131.00000,199.00000L131.00000,133.00000L127.00000,133.00000L127.00000,196.81522L59.50000,142.32727Z';

/** The Backplane mark, never recoloured. */
export const Mark: React.FC<{ size?: number }> = ({ size = 22 }) => (
  <svg
    className="brand-mark"
    width={size}
    height={size}
    viewBox="0 0 256 256"
    aria-hidden="true"
    focusable="false"
  >
    <path fill="#e6e9de" fillRule="evenodd" transform="translate(10.5 17.54)" d={MARK_PATH} />
  </svg>
);

export type IconName =
  | 'overview'
  | 'board'
  | 'library'
  | 'orders'
  | 'admin'
  | 'vm'
  | 'key'
  | 'bridge'
  | 'mail'
  | 'gate'
  | 'people';

const ICON_PATHS: Record<IconName, React.ReactNode> = {
  overview: (
    <>
      <rect x="2.5" y="2.5" width="4.5" height="4.5" />
      <rect x="9" y="2.5" width="4.5" height="4.5" />
      <rect x="2.5" y="9" width="4.5" height="4.5" />
      <rect x="9" y="9" width="4.5" height="4.5" />
    </>
  ),
  board: (
    <>
      <rect x="2.5" y="3.5" width="11" height="9" />
      <rect x="6" y="6" width="4" height="4" />
      <path d="M2.5 8H6M10 8h3.5M8 3.5V6M8 10v2.5" />
    </>
  ),
  library: (
    <>
      <path d="M3.5 2.5v11M6.5 2.5v11M9.2 3l3.3 10.2" />
      <path d="M2 13.5h12" />
    </>
  ),
  orders: (
    <>
      <path d="M2.5 5.5 8 2.5l5.5 3v5L8 13.5l-5.5-3z" />
      <path d="M2.5 5.5 8 8.5l5.5-3M8 8.5v5" />
    </>
  ),
  admin: (
    <>
      <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
      <rect x="4.5" y="3" width="2.5" height="3" fill="currentColor" />
      <rect x="9.5" y="6.5" width="2.5" height="3" fill="currentColor" />
      <rect x="5.5" y="10" width="2.5" height="3" fill="currentColor" />
    </>
  ),
  vm: (
    <>
      <rect x="2.5" y="3" width="11" height="4" />
      <rect x="2.5" y="9" width="11" height="4" />
      <path d="M4.5 5h1M4.5 11h1" />
    </>
  ),
  key: (
    <>
      <rect x="2.5" y="6" width="5" height="5" />
      <path d="M7.5 8.5h6M11 8.5V11M13.5 8.5v2" />
    </>
  ),
  bridge: (
    <>
      <rect x="2" y="6" width="4" height="4" />
      <rect x="10" y="6" width="4" height="4" />
      <path d="M6 8h4" />
    </>
  ),
  mail: (
    <>
      <rect x="2.5" y="3.5" width="11" height="9" />
      <path d="m2.5 4 5.5 4.5L13.5 4" />
    </>
  ),
  gate: (
    <>
      <path d="M3 13.5v-8L8 2.5l5 3v8" />
      <path d="m6 9 1.5 1.5L10.5 7.5" />
    </>
  ),
  people: (
    <>
      <rect x="5.5" y="2.5" width="5" height="5" />
      <path d="M2.5 13.5v-3h11v3" />
    </>
  ),
};

export const Icon: React.FC<{ name: IconName; size?: number }> = ({ name, size = 16 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.2"
    strokeLinecap="square"
    aria-hidden="true"
    focusable="false"
  >
    {ICON_PATHS[name]}
  </svg>
);

/** Square status dot plus label: the one status idiom used everywhere. */
export const Status: React.FC<{ tone?: Tone; pulse?: boolean; children: React.ReactNode }> = ({
  tone = 'plain',
  pulse,
  children,
}) => (
  <span className={`status${tone === 'plain' ? '' : ` s-${tone}`}${pulse ? ' pulse' : ''}`}>
    {children}
  </span>
);

export const Tag: React.FC<{ tone?: Tone; children: React.ReactNode }> = ({
  tone = 'plain',
  children,
}) => (
  <span className={`tag${tone === 'plain' || tone === 'idle' ? '' : ` t-${tone}`}`}>{children}</span>
);

interface PanelProps {
  title: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

/** Bordered section with a mono caption row. Children sit flush: wrap in `.panel-body` to pad. */
export const Panel: React.FC<PanelProps> = ({ title, meta, actions, children, className }) => (
  <section className={`panel${className ? ` ${className}` : ''}`}>
    <header className="panel-head">
      <div className="row tight nowrap trunc">
        <h3 className="panel-title">{title}</h3>
        {meta !== undefined && <span className="panel-meta">{meta}</span>}
      </div>
      {actions && <div className="row tight nowrap">{actions}</div>}
    </header>
    {children}
  </section>
);

interface EmptyProps {
  title: string;
  children?: React.ReactNode;
  actions?: React.ReactNode;
  icon?: IconName;
  variant?: 'default' | 'compact' | 'canvas';
}

export const Empty: React.FC<EmptyProps> = ({
  title,
  children,
  actions,
  icon,
  variant = 'default',
}) => (
  <div className={`empty${variant === 'default' ? '' : ` ${variant}`}`}>
    {icon && (
      <span className="empty-glyph">
        <Icon name={icon} size={variant === 'compact' ? 22 : 32} />
      </span>
    )}
    <div className="empty-title">{title}</div>
    {children && <div className="empty-hint">{children}</div>}
    {actions && <div className="empty-actions">{actions}</div>}
  </div>
);

interface StatProps {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  tone?: Tone;
  onClick?: () => void;
}

export const Stat: React.FC<StatProps> = ({ label, value, sub, tone, onClick }) => {
  const body = (
    <>
      <span className="stat-label">{label}</span>
      <span className={`stat-value${tone && tone !== 'plain' ? ` c-${tone}` : ''}`}>{value}</span>
      {sub !== undefined && <span className="stat-sub">{sub}</span>}
    </>
  );
  return onClick ? (
    <button type="button" className="stat" onClick={onClick}>
      {body}
    </button>
  ) : (
    <div className="stat">{body}</div>
  );
};

interface PageHeadProps {
  num: string;
  eyebrow: string;
  title: string;
  sub?: React.ReactNode;
  children?: React.ReactNode;
}

export const PageHead: React.FC<PageHeadProps> = ({ num, eyebrow, title, sub, children }) => (
  <header className="page-head">
    <div>
      <div className="eyebrow">
        <span className="eyebrow-num">{num}</span>
        {eyebrow}
      </div>
      <h1 className="page-title">{title}</h1>
      {sub && <p className="page-sub">{sub}</p>}
    </div>
    {children && <div className="page-actions">{children}</div>}
  </header>
);
