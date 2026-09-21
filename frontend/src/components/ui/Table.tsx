import React from 'react'

export interface TableProps extends React.TableHTMLAttributes<HTMLTableElement> {
  containerStyle?: React.CSSProperties
}

export const Table: React.FC<TableProps> = ({
  children,
  className = '',
  style,
  containerStyle,
  ...props
}) => {
  return (
    <div className="cg-table-responsive" style={containerStyle}>
      <table className={`cg-table ${className}`} style={style} {...props}>
        {children}
      </table>
    </div>
  )
}
